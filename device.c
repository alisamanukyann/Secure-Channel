/*
 * device.c - Encrypting UDP tunnel endpoint (runs on Device1 and Device2).
 *
 * Captures Ethernet frames from the attached PC, encrypts them with AES-256-GCM
 * and forwards them to the peer device inside UDP datagrams. The peer verifies,
 * decrypts and injects the original frame towards its own PC.
 *
 * Tunnel datagram (UDP payload):
 *     dir (1) | counter (8) | ciphertext (Ethernet frame) | GCM tag (16)
 *   nonce = dir | 0 0 0 | counter        AAD = dir | counter
 *
 * Usage: device <encrypt|decrypt> <lan_if> <local_ip> <peer_ip>
 *   encrypt = Device1 (DH client), decrypt = Device2 (DH server).
 *   Both modes handle both directions so that TCP ACKs can return.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>

#define CTL_PORT   8888                 /* TCP control channel (handshake) */
#define TUN_PORT   5555                 /* UDP data tunnel                 */
#define KEY_SZ     32
#define TAG_SZ     16
#define NONCE_SZ   12
#define HDR_SZ     9                    /* direction (1) + counter (8)     */
#define PUB_SZ     32
#define BUF_SZ     65536
#define MAX_FRAME  (1500 - 20 - 8 - HDR_SZ - TAG_SZ)   /* fits one 1500-byte packet */

static volatile sig_atomic_t running = 1;
static void on_signal(int s) { (void)s; running = 0; }

/* ---- I/O helpers ------------------------------------------------------- */

static int read_full(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        p += r; n -= r;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w; n -= w;
    }
    return 0;
}

/* ---- Checksums --------------------------------------------------------- */

static uint32_t csum_add(const uint8_t *p, size_t n, uint32_t sum)
{
    while (n > 1) { sum += (p[0] << 8) | p[1]; p += 2; n -= 2; }
    if (n) sum += p[0] << 8;
    return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Recompute IPv4 and TCP checksums before a frame is injected into a PC. */
static void fix_checksums(uint8_t *f, size_t len)
{
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) return;
    if (ntohs(((struct ethhdr *)f)->h_proto) != ETH_P_IP) return;

    struct iphdr *ip = (struct iphdr *)(f + sizeof(struct ethhdr));
    size_t ihl = ip->ihl * 4;
    if (ip->version != 4 || ihl < 20 || sizeof(struct ethhdr) + ihl > len) return;

    ip->check = 0;
    ip->check = htons(csum_fold(csum_add((uint8_t *)ip, ihl, 0)));

    if (ip->protocol != IPPROTO_TCP || (ntohs(ip->frag_off) & 0x3fff)) return;
    size_t tot = ntohs(ip->tot_len);
    if (tot < ihl + sizeof(struct tcphdr) || sizeof(struct ethhdr) + tot > len) return;

    size_t tcplen = tot - ihl;
    uint8_t *tcp = (uint8_t *)ip + ihl;
    tcp[16] = tcp[17] = 0;

    uint32_t sum = csum_add((uint8_t *)&ip->saddr, 8, 0);   /* pseudo-header */
    sum += IPPROTO_TCP + tcplen;
    uint16_t c = csum_fold(csum_add(tcp, tcplen, sum));
    tcp[16] = c >> 8;
    tcp[17] = c & 0xff;
}

/* ---- Key exchange: X25519 + HKDF-SHA256 -------------------------------- */

static void dh_handshake(int is_server, const char *local_ip, const char *peer_ip,
                         uint8_t key_out[KEY_SZ])
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        fprintf(stderr, "[DH] key generation failed\n"); exit(1);
    }
    EVP_PKEY_CTX_free(kctx);

    uint8_t my_pub[PUB_SZ], peer_pub[PUB_SZ];
    size_t plen = PUB_SZ;
    if (EVP_PKEY_get_raw_public_key(pkey, my_pub, &plen) <= 0 || plen != PUB_SZ) {
        fprintf(stderr, "[DH] cannot export public key\n"); exit(1);
    }

    /* Exchange public keys over TCP. */
    int comm;
    if (is_server) {
        int opt = 1, lfd = socket(AF_INET, SOCK_STREAM, 0);
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(CTL_PORT) };
        inet_pton(AF_INET, local_ip, &a.sin_addr);
        if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(lfd, 1) < 0) {
            perror("[DH] bind/listen"); exit(1);
        }
        printf("[DH] server waiting on %s:%d\n", local_ip, CTL_PORT); fflush(stdout);
        comm = accept(lfd, NULL, NULL);
        if (comm < 0) { perror("[DH] accept"); exit(1); }
        close(lfd);
    } else {
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(CTL_PORT) };
        inet_pton(AF_INET, peer_ip, &a.sin_addr);
        printf("[DH] client connecting to %s:%d\n", peer_ip, CTL_PORT); fflush(stdout);
        for (;;) {
            comm = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(comm, (struct sockaddr *)&a, sizeof(a)) == 0) break;
            close(comm);
            usleep(200000);
            if (!running) exit(1);
        }
    }
    if (write_full(comm, my_pub, PUB_SZ) < 0 || read_full(comm, peer_pub, PUB_SZ) < 0) {
        fprintf(stderr, "[DH] public key exchange failed\n"); exit(1);
    }
    close(comm);

    /* Shared secret. */
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, PUB_SZ);
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(pkey, NULL);
    uint8_t secret[32], zero[32] = {0};
    size_t slen = sizeof(secret);
    if (!peer || !dctx || EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, peer) <= 0 ||
        EVP_PKEY_derive(dctx, secret, &slen) <= 0 ||
        CRYPTO_memcmp(secret, zero, sizeof(zero)) == 0) {
        fprintf(stderr, "[DH] shared secret derivation failed\n"); exit(1);
    }

    /* Session key = HKDF-SHA256(secret, info = label | client_pub | server_pub). */
    static const char label[] = "secure-channel udp tunnel v1";
    uint8_t info[sizeof(label) - 1 + 2 * PUB_SZ];
    memcpy(info, label, sizeof(label) - 1);
    memcpy(info + sizeof(label) - 1,          is_server ? peer_pub : my_pub, PUB_SZ);
    memcpy(info + sizeof(label) - 1 + PUB_SZ, is_server ? my_pub : peer_pub, PUB_SZ);

    EVP_PKEY_CTX *hctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t klen = KEY_SZ;
    if (!hctx || EVP_PKEY_derive_init(hctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(hctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(hctx, (const unsigned char *)"secure-channel", 14) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(hctx, secret, sizeof(secret)) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(hctx, info, sizeof(info)) <= 0 ||
        EVP_PKEY_derive(hctx, key_out, &klen) <= 0) {
        fprintf(stderr, "[DH] key derivation failed\n"); exit(1);
    }

    /* Print a key fingerprint (never the key) so both sides can be compared. */
    uint8_t fp[32]; unsigned fpl = 0;
    EVP_Digest(key_out, KEY_SZ, fp, &fpl, EVP_sha256(), NULL);
    printf("[DH] session key established, fingerprint %02x%02x%02x%02x\n",
           fp[0], fp[1], fp[2], fp[3]);
    fflush(stdout);

    OPENSSL_cleanse(secret, sizeof(secret));
    EVP_PKEY_CTX_free(hctx); EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer); EVP_PKEY_free(pkey);
}

/* ---- AES-256-GCM ------------------------------------------------------- */

static EVP_CIPHER_CTX *cctx;

static void make_nonce(uint8_t nonce[NONCE_SZ], const uint8_t hdr[HDR_SZ])
{
    memset(nonce, 0, NONCE_SZ);
    nonce[0] = hdr[0];                  /* direction */
    memcpy(nonce + 4, hdr + 1, 8);      /* packet counter */
}

/* Writes hdr | ciphertext | tag to out; returns total length or -1. */
static int seal(const uint8_t *key, uint8_t dir, uint64_t ctr,
                const uint8_t *pt, int ptl, uint8_t *out)
{
    uint8_t nonce[NONCE_SZ];
    int l = 0, total;

    out[0] = dir;
    for (int i = 0; i < 8; i++) out[1 + i] = (uint8_t)(ctr >> (56 - 8 * i));
    make_nonce(nonce, out);

    EVP_CIPHER_CTX_reset(cctx);
    if (EVP_EncryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SZ, NULL) != 1 ||
        EVP_EncryptInit_ex(cctx, NULL, NULL, key, nonce) != 1 ||
        EVP_EncryptUpdate(cctx, NULL, &l, out, HDR_SZ) != 1 ||
        EVP_EncryptUpdate(cctx, out + HDR_SZ, &l, pt, ptl) != 1) return -1;
    total = l;
    if (EVP_EncryptFinal_ex(cctx, out + HDR_SZ + total, &l) != 1) return -1;
    total += l;
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, TAG_SZ, out + HDR_SZ + total) != 1)
        return -1;
    return HDR_SZ + total + TAG_SZ;
}

/* Verifies the tag and decrypts; returns plaintext length or -1 on failure. */
static int open_pkt(const uint8_t *key, const uint8_t *in, int inl, uint8_t *pt)
{
    uint8_t nonce[NONCE_SZ], tag[TAG_SZ];
    int ctl = inl - HDR_SZ - TAG_SZ, l = 0, total;

    make_nonce(nonce, in);
    memcpy(tag, in + HDR_SZ + ctl, TAG_SZ);

    EVP_CIPHER_CTX_reset(cctx);
    if (EVP_DecryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SZ, NULL) != 1 ||
        EVP_DecryptInit_ex(cctx, NULL, NULL, key, nonce) != 1 ||
        EVP_DecryptUpdate(cctx, NULL, &l, in, HDR_SZ) != 1 ||
        EVP_DecryptUpdate(cctx, pt, &l, in + HDR_SZ, ctl) != 1) return -1;
    total = l;
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG, TAG_SZ, tag) != 1) return -1;
    if (EVP_DecryptFinal_ex(cctx, pt + total, &l) != 1) return -1;
    return total + l;
}

/* ---- Replay protection (64-packet sliding window) ---------------------- */

typedef struct { uint64_t max, bitmap; int init; } replay_t;

static int replay_ok(const replay_t *r, uint64_t c)
{
    if (!r->init || c > r->max) return 1;
    uint64_t d = r->max - c;
    return d < 64 && !((r->bitmap >> d) & 1);
}

static void replay_mark(replay_t *r, uint64_t c)
{
    if (!r->init) { r->init = 1; r->max = c; r->bitmap = 1; return; }
    if (c > r->max) {
        uint64_t s = c - r->max;
        r->bitmap = (s >= 64) ? 0 : (r->bitmap << s);
        r->bitmap |= 1;
        r->max = c;
    } else {
        r->bitmap |= 1ULL << (r->max - c);
    }
}

/* ---- Main -------------------------------------------------------------- */

static void big_buf(int fd, int opt)
{
    int sz = 4 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, opt == SO_RCVBUF ? SO_RCVBUFFORCE : SO_SNDBUFFORCE,
                   &sz, sizeof(sz)) < 0)
        setsockopt(fd, SOL_SOCKET, opt, &sz, sizeof(sz));
}

int main(int argc, char *argv[])
{
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <encrypt|decrypt> <lan_if> <local_ip> <peer_ip>\n", argv[0]);
        return 1;
    }
    int encrypt_mode = !strcmp(argv[1], "encrypt");
    if (!encrypt_mode && strcmp(argv[1], "decrypt")) {
        fprintf(stderr, "mode must be 'encrypt' or 'decrypt'\n");
        return 1;
    }
    const char *lan_if = argv[2], *local_ip = argv[3], *peer_ip = argv[4];
    const uint8_t my_dir   = encrypt_mode ? 1 : 2;   /* keeps nonces of both directions disjoint */
    const uint8_t peer_dir = encrypt_mode ? 2 : 1;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    uint8_t key[KEY_SZ];
    dh_handshake(!encrypt_mode, local_ip, peer_ip, key);
    cctx = EVP_CIPHER_CTX_new();

    /* LAN side: promiscuous raw socket on an interface without an IP address. */
    int ifindex = if_nametoindex(lan_if);
    if (!ifindex) { perror("if_nametoindex"); return 1; }
    int lan = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (lan < 0) { perror("socket(AF_PACKET)"); return 1; }
    struct sockaddr_ll sll = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL),
                               .sll_ifindex = ifindex };
    if (bind(lan, (struct sockaddr *)&sll, sizeof(sll)) < 0) { perror("bind lan"); return 1; }
    struct packet_mreq mr = { .mr_ifindex = ifindex, .mr_type = PACKET_MR_PROMISC };
    setsockopt(lan, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
    big_buf(lan, SO_RCVBUF);

    /* Tunnel side: UDP socket towards the peer device. */
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in la = { .sin_family = AF_INET, .sin_port = htons(TUN_PORT) };
    struct sockaddr_in pa = { .sin_family = AF_INET, .sin_port = htons(TUN_PORT) };
    inet_pton(AF_INET, local_ip, &la.sin_addr);
    inet_pton(AF_INET, peer_ip,  &pa.sin_addr);
    if (bind(udp, (struct sockaddr *)&la, sizeof(la)) < 0) { perror("bind udp"); return 1; }
    big_buf(udp, SO_RCVBUF);
    big_buf(udp, SO_SNDBUF);

    printf("[%s] tunnel ready: %s <-> UDP %s:%d -> %s:%d\n",
           encrypt_mode ? "DEVICE1/encrypt" : "DEVICE2/decrypt",
           lan_if, local_ip, TUN_PORT, peer_ip, TUN_PORT);
    fflush(stdout);

    static uint8_t frame[BUF_SZ], pkt[BUF_SZ], out[BUF_SZ];
    uint64_t tx_ctr = 0, n_tx = 0, n_rx = 0, n_auth_fail = 0, n_replay = 0, n_big = 0;
    replay_t rwin = {0};
    struct pollfd fds[2] = { { .fd = lan, .events = POLLIN }, { .fd = udp, .events = POLLIN } };

    while (running) {
        if (poll(fds, 2, 500) < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        /* LAN -> tunnel: capture, encrypt, send. */
        if (fds[0].revents & POLLIN) {
            struct sockaddr_ll from; socklen_t fl = sizeof(from);
            ssize_t len = recvfrom(lan, frame, sizeof(frame), 0, (struct sockaddr *)&from, &fl);
            if (len >= (ssize_t)sizeof(struct ethhdr) && from.sll_pkttype != PACKET_OUTGOING) {
                if (len > MAX_FRAME && !n_big++)
                    fprintf(stderr, "[warn] %zd-byte frame exceeds %d: UDP will fragment "
                                    "(check MSS clamp)\n", len, MAX_FRAME);
                int n = seal(key, my_dir, tx_ctr++, frame, (int)len, out);
                if (n > 0 && sendto(udp, out, n, 0, (struct sockaddr *)&pa, sizeof(pa)) > 0)
                    n_tx++;
            }
        }

        /* Tunnel -> LAN: receive, verify tag, decrypt, inject. */
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in src; socklen_t sl = sizeof(src);
            ssize_t n = recvfrom(udp, pkt, sizeof(pkt), 0, (struct sockaddr *)&src, &sl);
            if (n < HDR_SZ + TAG_SZ + (ssize_t)sizeof(struct ethhdr) ||
                src.sin_addr.s_addr != pa.sin_addr.s_addr || pkt[0] != peer_dir)
                continue;

            uint64_t ctr = 0;
            for (int i = 0; i < 8; i++) ctr = (ctr << 8) | pkt[1 + i];
            if (!replay_ok(&rwin, ctr)) { n_replay++; continue; }

            int pl = open_pkt(key, pkt, (int)n, out);
            if (pl < (int)sizeof(struct ethhdr)) { n_auth_fail++; continue; }
            replay_mark(&rwin, ctr);

            fix_checksums(out, pl);
            struct sockaddr_ll to = { .sll_family = AF_PACKET, .sll_ifindex = ifindex };
            if (sendto(lan, out, pl, 0, (struct sockaddr *)&to, sizeof(to)) > 0)
                n_rx++;
        }
    }

    printf("[stats] sent: %llu  received: %llu  auth failures: %llu  replays dropped: %llu\n",
           (unsigned long long)n_tx, (unsigned long long)n_rx,
           (unsigned long long)n_auth_fail, (unsigned long long)n_replay);
    OPENSSL_cleanse(key, sizeof(key));
    EVP_CIPHER_CTX_free(cctx);
    return 0;
}

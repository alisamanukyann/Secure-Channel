#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#define BUF_SZ   65535
#define TAG_SZ   16
#define KEY_SZ   32
#define NONCE_SZ 12

/* Internet checksum */
unsigned short calc_chk(unsigned short *ptr, int nbytes)
{
    long sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes > 0)
        sum += *(unsigned char *)ptr;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)(~sum);
}

/* Recalculate IP + TCP checksums (handles TCP options correctly) */
void update_chksums(struct iphdr *iph, struct tcphdr *tcph,
                    unsigned char *payload, int plen)
{
    int ip_hl  = iph->ihl * 4;
    int tcp_hl = tcph->doff * 4;

    iph->check = 0;
    iph->check = calc_chk((unsigned short *)iph, ip_hl);

    tcph->check = 0;

    struct {
        uint32_t src, dst;
        uint8_t  res, proto;
        uint16_t len;
    } psh = {
        .src   = iph->saddr,
        .dst   = iph->daddr,
        .res   = 0,
        .proto = IPPROTO_TCP,
        .len   = htons(tcp_hl + plen)
    };

    int total = sizeof(psh) + tcp_hl + plen;
    unsigned char *buf = malloc(total);
    if (!buf) return;

    memcpy(buf, &psh, sizeof(psh));
    memcpy(buf + sizeof(psh), tcph, tcp_hl);          /* full header + options */
    memcpy(buf + sizeof(psh) + tcp_hl, payload, plen);

    tcph->check = calc_chk((unsigned short *)buf, total);
    free(buf);
}

/*
 * Diffie-Hellman (X25519) over a control TCP connection.
 * Device2 (decrypt) = server, Device1 (encrypt) = client.
 * Control addresses are 10.0.0.1 (Dev1) ↔ 10.0.0.2 (Dev2)
 */
void dh_handshake(int is_server, unsigned char *key_out)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "DH keygen failed\n");
        exit(1);
    }
    EVP_PKEY_CTX_free(ctx);

    size_t pub_len = 0;
    EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_len);
    unsigned char *pub_key = malloc(pub_len);
    EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub_key, pub_len, &pub_len);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int comm = sock;

    if (is_server) {
        int opt = 1;
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port   = htons(8888),
            .sin_addr.s_addr = INADDR_ANY
        };
        if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
            listen(lfd, 1) < 0) {
            perror("DH server bind/listen");
            exit(1);
        }
        printf("[DH] Server waiting on :8888 ...\n");
        fflush(stdout);
        comm = accept(lfd, NULL, NULL);
        if (comm < 0) {
            perror("DH accept");
            exit(1);
        }
        close(lfd);
        printf("[DH] Client connected\n");
    } else {
        /* client – wait until server is ready */
        sleep(1);
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port   = htons(8888)
        };
        inet_pton(AF_INET, "10.0.0.2", &addr.sin_addr);

        printf("[DH] Connecting to 10.0.0.2:8888 ...\n");
        fflush(stdout);
        while (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
            usleep(100000);
        printf("[DH] Connected\n");
    }

    /* exchange public keys */
    uint32_t net_len = htonl(pub_len);
    write(comm, &net_len, sizeof(net_len));
    write(comm, pub_key, pub_len);

    read(comm, &net_len, sizeof(net_len));
    size_t p_len = ntohl(net_len);
    unsigned char *p_key = malloc(p_len);
    read(comm, p_key, p_len);

    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, p_key, p_len);
    EVP_PKEY_CTX *d_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_derive_init(d_ctx);
    EVP_PKEY_derive_set_peer(d_ctx, peer);

    size_t klen = KEY_SZ;
    if (EVP_PKEY_derive(d_ctx, key_out, &klen) <= 0) {
        fprintf(stderr, "DH derive failed\n");
        exit(1);
    }

    printf("[DH] Shared session key established (%zu bytes)\n", klen);
    fflush(stdout);

    EVP_PKEY_CTX_free(d_ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(pkey);
    free(pub_key);
    free(p_key);
    if (comm != sock) close(comm);
    close(sock);
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <encrypt|decrypt> <rx_if> <tx_if>\n", argv[0]);
        return 1;
    }

    int encrypt_mode = !strcmp(argv[1], "encrypt");
    const char *rx_name = argv[2];
    const char *tx_name = argv[3];

    unsigned char key[KEY_SZ];
    /* decrypt side is the DH server */
    dh_handshake(!encrypt_mode, key);

    uint32_t counter = 0;

    int rx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    int tx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rx < 0 || tx < 0) {
        perror("socket");
        return 1;
    }

    /* bind RX socket to the input interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, rx_name, IFNAMSIZ - 1);
    if (ioctl(rx, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX rx");
        return 1;
    }
    int rx_ifindex = ifr.ifr_ifindex;

    struct sockaddr_ll rx_sa = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = rx_ifindex
    };
    if (bind(rx, (struct sockaddr *)&rx_sa, sizeof(rx_sa)) < 0) {
        perror("bind rx");
        return 1;
    }

    /* TX ifindex */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tx_name, IFNAMSIZ - 1);
    if (ioctl(tx, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX tx");
        return 1;
    }
    int tx_ifindex = ifr.ifr_ifindex;

    struct sockaddr_ll sa = {
        .sll_family  = AF_PACKET,
        .sll_ifindex = tx_ifindex,
        .sll_halen   = 0
    };

    printf("[%s] listening on %s → forwarding to %s\n",
           encrypt_mode ? "ENCRYPT" : "DECRYPT", rx_name, tx_name);
    fflush(stdout);

    unsigned char buf[BUF_SZ];

    while (1) {
        ssize_t len = recv(rx, buf, BUF_SZ, 0);
        if (len < (ssize_t)(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
            continue;

        struct ethhdr *eth = (struct ethhdr *)buf;
        struct iphdr  *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));

        /* non-TCP → just forward */
        if (iph->protocol != IPPROTO_TCP) {
            memcpy(sa.sll_addr, eth->h_dest, ETH_ALEN);
            sendto(tx, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
            continue;
        }

        int ip_hl  = iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr *)(buf + sizeof(struct ethhdr) + ip_hl);
        int tcp_hl = tcph->doff * 4;
        int hlen   = sizeof(struct ethhdr) + ip_hl + tcp_hl;
        int plen   = ntohs(iph->tot_len) - ip_hl - tcp_hl;

        if (plen < 0 || hlen + plen > len)
            continue;

        /* pure ACK / no payload → forward unchanged */
        if (plen == 0) {
            memcpy(sa.sll_addr, eth->h_dest, ETH_ALEN);
            sendto(tx, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
            continue;
        }

        unsigned char *payload = buf + hlen;
        unsigned char nonce[NONCE_SZ] = {0};
        memcpy(nonce, &counter, sizeof(counter));   /* unique per packet */

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        if (encrypt_mode) {
            unsigned char ct[BUF_SZ], tag[TAG_SZ];
            int outl = 0, ctl = 0;

            EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SZ, NULL);
            EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
            EVP_EncryptUpdate(ctx, ct, &outl, payload, plen);
            ctl = outl;
            EVP_EncryptFinal_ex(ctx, ct + outl, &outl);
            ctl += outl;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SZ, tag);
            EVP_CIPHER_CTX_free(ctx);

            memcpy(payload, ct, ctl);
            memcpy(payload + ctl, tag, TAG_SZ);

            int new_plen = ctl + TAG_SZ;
            iph->tot_len = htons(ip_hl + tcp_hl + new_plen);
            update_chksums(iph, tcph, payload, new_plen);
            counter++;

            memcpy(sa.sll_addr, eth->h_dest, ETH_ALEN);
            sendto(tx, buf, sizeof(struct ethhdr) + ip_hl + tcp_hl + new_plen,
                   0, (struct sockaddr *)&sa, sizeof(sa));
        } else {
            /* decrypt side */
            if (plen < TAG_SZ) {
                memcpy(sa.sll_addr, eth->h_dest, ETH_ALEN);
                sendto(tx, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
                continue;
            }

            int ctl = plen - TAG_SZ;
            unsigned char pt[BUF_SZ];
            int outl = 0, ptl = 0;

            EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SZ, NULL);
            EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
            EVP_DecryptUpdate(ctx, pt, &outl, payload, ctl);
            ptl = outl;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SZ, payload + ctl);

            int ok = EVP_DecryptFinal_ex(ctx, pt + outl, &outl);
            EVP_CIPHER_CTX_free(ctx);

            if (ok <= 0) {
                /* authentication failed – drop */
                continue;
            }

            memcpy(payload, pt, ptl + outl);
            int new_plen = ptl + outl;
            iph->tot_len = htons(ip_hl + tcp_hl + new_plen);
            update_chksums(iph, tcph, payload, new_plen);
            counter++;

            memcpy(sa.sll_addr, eth->h_dest, ETH_ALEN);
            sendto(tx, buf, sizeof(struct ethhdr) + ip_hl + tcp_hl + new_plen,
                   0, (struct sockaddr *)&sa, sizeof(sa));
        }
    }
    return 0;
}
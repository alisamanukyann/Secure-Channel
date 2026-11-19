# Secure Channel over a UDP Tunnel

A prototype of an inline encrypted channel on Linux. PC1 sends a file over TCP to PC2; two device
nodes transparently encrypt the traffic with AES-256-GCM and carry it through a **UDP tunnel**.
A passive MITM node between the devices sees only ciphertext.

```
 ns_pc1        ns_dev1               ns_mitm            ns_dev2        ns_pc2
 sender --- device (encrypt) ======= bridge br0 ======= device (decrypt) --- receiver
 192.168.100.1   LAN side: raw, no IP   10.0.0.1 <-> 10.0.0.2   LAN side: raw, no IP   192.168.100.2
                        \____ AES-256-GCM inside UDP :5555 ____/
```
Five namespaces, all links are veth pairs. The PCs believe they share one LAN.

## Files
| File | Role |
|---|---|
| `sender.c` | PC1 - TCP client: `./sender <IP> <Port> <File>` |
| `receiver.c` | PC2 - TCP server: `./receiver <Port> <OutputFile>` |
| `device.c` | Tunnel endpoint, identical code on both devices |
| `setup_net.sh` | Creates namespaces, veth links, addresses, MITM bridge, MSS clamp |
| `run_test.sh` | End-to-end test: build, transfer, sha256 check, MITM capture check |

## Design
**Device behaviour** (`./device <encrypt|decrypt> <lan_if> <local_ip> <peer_ip>`)
1. **Handshake:** X25519 key exchange over a TCP control connection (port 8888); the session key is derived with HKDF-SHA256. `encrypt` (Device1) is the client, `decrypt` (Device2) the server.
2. **Capture:** a promiscuous `AF_PACKET` raw socket on the LAN-side interface (no IP address) reads every Ethernet frame from the PC.
3. **Encrypt and tunnel:** each frame is encrypted with AES-256-GCM (OpenSSL) and sent to the peer in a UDP datagram (port 5555).
4. **Verify and deliver:** the peer checks the 16-byte tag, rejects forged or replayed packets, decrypts, and injects the original frame towards its PC.
5. Both devices perform both directions, so TCP ACKs can return.

**Tunnel datagram**
```
 dir (1) | counter (8) | ciphertext (Ethernet frame) | GCM tag (16)     -> UDP payload
```
- Nonce = direction + 64-bit counter, unique per packet and per direction.
- `dir | counter` is authenticated as AAD.
- A 64-packet replay window tolerates UDP loss and reordering.

**MSS clamp:** the tunnel adds 67 bytes per packet (UDP 8, IP 20, header 9, tag 16, inner Ethernet 14). The PCs clamp the TCP MSS to 1360 so every tunnel packet fits in 1500 bytes without fragmentation.

## Requirements
Linux, root privileges, `gcc`, `libssl-dev`, `iproute2`, `ethtool`, `iptables`, `tcpdump`.

## Usage
Automatic test (128 MB by default):
```bash
sudo bash ./run_test.sh [size_in_MB]
```
Manual run:
```bash
sudo ./setup_net.sh
gcc -O2 -o device device.c -lcrypto && gcc -O2 -o sender sender.c && gcc -O2 -o receiver receiver.c

sudo ip netns exec ns_dev2 ./device decrypt veth_dev2_out 10.0.0.2 10.0.0.1 &
sudo ip netns exec ns_dev1 ./device encrypt veth_dev1_in  10.0.0.1 10.0.0.2 &
sudo ip netns exec ns_pc2  ./receiver 5000 received.bin &
sudo ip netns exec ns_pc1  ./sender 192.168.100.2 5000 testfile.bin

sha256sum testfile.bin received.bin
sudo ip netns exec ns_mitm tcpdump -i br0 -n -X      # attacker's view: UDP :5555 ciphertext only
```
If the project folder is mounted `noexec`, copy it to `/tmp` first.

## Verification (128 MB transfer)
- `sha256sum` of the sent and received file is identical.
- Both devices derive the same key (matching fingerprints) and report 0 authentication failures.
- A plaintext marker inside the file is visible on the PC1 link but absent from the MITM capture, which shows only UDP traffic between 10.0.0.1 and 10.0.0.2 on port 5555.

## Limitations
- The key exchange is unauthenticated, so an *active* attacker could substitute keys. The MITM here is passive; for an active one, sign the public keys or use a pre-shared key.
- Frames are encrypted whole (Ethernet header included), which hides all headers but adds the overhead above.

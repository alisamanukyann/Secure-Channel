# Secure Inline TCP Communication Prototype

A Linux-based prototype of a secure inline communication channel between two hosts operating over network namespaces and `veth` pairs:
`PC1 → Device1 (Encrypt) → MITM (Bridge) → Device2 (Decrypt) → PC2`

## Key Features
* **Layer 2 Inline Processing:** Devices operate transparently using raw sockets (`AF_PACKET`) in promiscuous mode without requiring IP addresses on their forwarding interfaces.
* **Cryptographic Handshake:** Implements an active Diffie-Hellman (X25519) key exchange over a TCP control channel during startup to derive a shared 256-bit session key.
* **Authenticated Encryption:** Encrypts only the TCP payload using **AES-256-GCM**, appending a 16-byte authentication tag to ensure confidentiality and integrity.
* **Replay Protection:** Ensures a unique nonce is utilized for every encrypted packet using a per-session packet counter.
* **Checksum & Packet Integrity:** Automatically recomputes IP headers and TCP pseudo-header checksums, adjusting MSS to prevent fragmentation.
* **Bit-for-bit Verification:** Tested with large file transfers (128MB) verified via `sha256sum`.

## Project Structure
* `setup_net.sh`: Automated network namespace, `veth` pair, bridge, and MSS clamping configuration script.
* `device.c`: Inline cryptographic processor handling raw packet interception, DH handshake, AES-GCM encryption/decryption, and checksum updates.
* `sender.c`: TCP client application (PC1) for transmitting payload files.
* `receiver.c`: TCP server application (PC2) for receiving and saving transmitted files.

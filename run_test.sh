#!/bin/bash
# Full demo: build -> network -> handshake -> 128 MB transfer -> sha256 check -> MITM sniff check.
# Usage: sudo ./run_test.sh [size_in_MB]
cd "$(dirname "$0")"
[ "$EUID" -eq 0 ] || exec sudo "$0" "$@"
SIZE_MB=${1:-128}
mkdir -p logs

echo "== build =="
gcc -O2 -Wall -o device   device.c   -lcrypto || exit 1
gcc -O2 -Wall -o sender   sender.c            || exit 1
gcc -O2 -Wall -o receiver receiver.c          || exit 1

echo "== network =="
./setup_net.sh > logs/setup.log 2>&1 || { echo "setup failed, see logs/setup.log"; exit 1; }

cleanup() {
    kill -INT $DEV1_PID $DEV2_PID 2>/dev/null; sleep 0.5
    kill $DEV1_PID $DEV2_PID $REC_PID $TD1 $TD2 2>/dev/null
    for ns in ns_pc1 ns_dev1 ns_mitm ns_dev2 ns_pc2; do ip netns del $ns 2>/dev/null; done
}
trap cleanup EXIT

echo "== test file (${SIZE_MB} MB: plaintext marker + random data) =="
yes "CONFIDENTIAL-PLAINTEXT-MARKER" | head -c 200000 > testfile.bin
head -c $((SIZE_MB*1024*1024 - 200000)) /dev/urandom >> testfile.bin
rm -f received.bin

echo "== sniffers: MITM bridge (what an attacker sees) and PC1 link (plain control) =="
ip netns exec ns_mitm tcpdump -i br0      -n -s 0 -c 3000 -w logs/mitm.pcap      2>/dev/null & TD1=$!
ip netns exec ns_pc1  tcpdump -i veth_pc1 -n -s 0 -c 3000 -w logs/pc1_plain.pcap 2>/dev/null & TD2=$!
sleep 1

echo "== devices (handshake + tunnel) =="
ip netns exec ns_dev2 ./device decrypt veth_dev2_out 10.0.0.2 10.0.0.1 > logs/dev2.log 2>&1 & DEV2_PID=$!
sleep 0.5
ip netns exec ns_dev1 ./device encrypt veth_dev1_in  10.0.0.1 10.0.0.2 > logs/dev1.log 2>&1 & DEV1_PID=$!
for i in $(seq 50); do
    grep -q "tunnel ready" logs/dev1.log && grep -q "tunnel ready" logs/dev2.log && break
    sleep 0.2
done
cat logs/dev1.log logs/dev2.log

echo "== transfer =="
ip netns exec ns_pc2 ./receiver 5000 received.bin > logs/receiver.log 2>&1 & REC_PID=$!
sleep 1
START=$(date +%s.%N)
ip netns exec ns_pc1 ./sender 192.168.100.2 5000 testfile.bin
wait $REC_PID
END=$(date +%s.%N)
cat logs/receiver.log
printf "elapsed: %.1f s\n" "$(echo "$END - $START" | bc 2>/dev/null || echo 0)"

echo "== integrity (sha256) =="
sha256sum testfile.bin received.bin
if [ "$(sha256sum < testfile.bin)" = "$(sha256sum < received.bin)" ]; then
    echo "RESULT: files are IDENTICAL"
else
    echo "RESULT: files DIFFER"
fi

echo "== MITM view =="
sleep 1
grep -a -q CONFIDENTIAL-PLAINTEXT-MARKER logs/pc1_plain.pcap && echo "PC1 link : marker visible in plaintext (control, expected)"
if grep -a -q CONFIDENTIAL-PLAINTEXT-MARKER logs/mitm.pcap; then
    echo "MITM link: marker FOUND  -> NOT encrypted!"
else
    echo "MITM link: marker not found -> traffic is encrypted"
fi
echo "UDP tunnel packets seen by MITM:"
tcpdump -nr logs/mitm.pcap udp port 5555 2>/dev/null | head -3

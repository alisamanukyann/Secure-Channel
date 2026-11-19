#!/bin/bash
# setup_net.sh - Builds the test topology (run as root):
#
#   ns_pc1 -- ns_dev1 -- ns_mitm -- ns_dev2 -- ns_pc2     (all links are veth pairs)
#
# PC1/PC2 share 192.168.100.0/24. Devices tunnel over 10.0.0.0/24 through the MITM bridge.
set -x

NS="ns_pc1 ns_dev1 ns_mitm ns_dev2 ns_pc2"

# Namespaces (recreated from scratch)
for ns in $NS; do ip netns del $ns 2>/dev/null; done
for ns in $NS; do ip netns add $ns; done

# veth links: PC1-Dev1, Dev1-MITM, MITM-Dev2, Dev2-PC2
ip link add veth_pc1      type veth peer name veth_dev1_in
ip link add veth_dev1_out type veth peer name veth_mitm_in
ip link add veth_mitm_out type veth peer name veth_dev2_in
ip link add veth_dev2_out type veth peer name veth_pc2

ip link set veth_pc1      netns ns_pc1
ip link set veth_dev1_in  netns ns_dev1
ip link set veth_dev1_out netns ns_dev1
ip link set veth_mitm_in  netns ns_mitm
ip link set veth_mitm_out netns ns_mitm
ip link set veth_dev2_in  netns ns_dev2
ip link set veth_dev2_out netns ns_dev2
ip link set veth_pc2      netns ns_pc2

# Disable IPv6 so that NDP/MLD traffic is not tunneled
for ns in $NS; do
    ip netns exec $ns sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
done

# Bring interfaces up
for ns in $NS; do ip netns exec $ns ip link set lo up; done
ip netns exec ns_pc1  ip link set veth_pc1 up
ip netns exec ns_dev1 ip link set veth_dev1_in up
ip netns exec ns_dev1 ip link set veth_dev1_out up
ip netns exec ns_mitm ip link set veth_mitm_in up
ip netns exec ns_mitm ip link set veth_mitm_out up
ip netns exec ns_dev2 ip link set veth_dev2_in up
ip netns exec ns_dev2 ip link set veth_dev2_out up
ip netns exec ns_pc2  ip link set veth_pc2 up

# End hosts: same subnet, unaware of the tunnel
ip netns exec ns_pc1 ip addr add 192.168.100.1/24 dev veth_pc1
ip netns exec ns_pc2 ip addr add 192.168.100.2/24 dev veth_pc2

# Devices, LAN side: no IP, promiscuous (frames are handled via AF_PACKET)
ip netns exec ns_dev1 ip link set veth_dev1_in  promisc on
ip netns exec ns_dev2 ip link set veth_dev2_out promisc on

# Devices, tunnel side: addresses for the UDP tunnel and key exchange
ip netns exec ns_dev1 ip addr add 10.0.0.1/24 dev veth_dev1_out
ip netns exec ns_dev2 ip addr add 10.0.0.2/24 dev veth_dev2_in

# MITM: passive bridge, forwards traffic and can be sniffed
ip netns exec ns_mitm ip link add name br0 type bridge
ip netns exec ns_mitm ip link set veth_mitm_in  master br0
ip netns exec ns_mitm ip link set veth_mitm_out master br0
ip netns exec ns_mitm ip link set br0 up

# Disable offloads: raw sockets need complete, MTU-sized frames
for pair in ns_pc1:veth_pc1 ns_dev1:veth_dev1_in ns_dev1:veth_dev1_out \
            ns_mitm:veth_mitm_in ns_mitm:veth_mitm_out \
            ns_dev2:veth_dev2_in ns_dev2:veth_dev2_out ns_pc2:veth_pc2; do
    ip netns exec ${pair%%:*} ethtool -K ${pair##*:} tx off rx off tso off gso off gro off 2>/dev/null
done

# MSS clamp: tunnel overhead is 67 bytes (UDP 8 + IP 20 + header 9 + tag 16 + Ethernet 14),
# so a smaller MSS keeps every tunnel packet within 1500 bytes.
for ns in ns_pc1 ns_pc2; do
    ip netns exec $ns iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --set-mss 1360 || echo "WARNING: TCPMSS rule failed in $ns"
done

echo "Environment ready"

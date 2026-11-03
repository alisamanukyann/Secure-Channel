#!/bin/bash
set -x

# Remove existing namespaces
for ns in ns_pc1 ns_dev1 ns_mitm ns_dev2 ns_pc2; do
    ip netns del $ns 2>/dev/null
done

# Create namespaces
for ns in ns_pc1 ns_dev1 ns_mitm ns_dev2 ns_pc2; do
    ip netns add $ns
done

# veth pairs
ip link add veth_pc1 type veth peer name veth_dev1_in
ip link set veth_pc1 netns ns_pc1
ip link set veth_dev1_in netns ns_dev1

ip link add veth_dev1_out type veth peer name veth_mitm_in
ip link set veth_dev1_out netns ns_dev1
ip link set veth_mitm_in netns ns_mitm

ip link add veth_mitm_out type veth peer name veth_dev2_in
ip link set veth_mitm_out netns ns_mitm
ip link set veth_dev2_in netns ns_dev2

ip link add veth_dev2_out type veth peer name veth_pc2
ip link set veth_dev2_out netns ns_dev2
ip link set veth_pc2 netns ns_pc2

# bring everything up
for ns in ns_pc1 ns_dev1 ns_mitm ns_dev2 ns_pc2; do
    ip netns exec $ns ip link set lo up
done

ip netns exec ns_pc1  ip link set veth_pc1 up
ip netns exec ns_dev1 ip link set veth_dev1_in up
ip netns exec ns_dev1 ip link set veth_dev1_out up
ip netns exec ns_mitm ip link set veth_mitm_in up
ip netns exec ns_mitm ip link set veth_mitm_out up
ip netns exec ns_dev2 ip link set veth_dev2_in up
ip netns exec ns_dev2 ip link set veth_dev2_out up
ip netns exec ns_pc2  ip link set veth_pc2 up

# endpoint addresses
ip netns exec ns_pc1 ip addr add 192.168.100.1/24 dev veth_pc1
ip netns exec ns_pc2 ip addr add 192.168.100.2/24 dev veth_pc2

# control plane for Diffie-Hellman (Device1 ↔ Device2)
ip netns exec ns_dev1 ip addr add 10.0.0.1/24 dev veth_dev1_out
ip netns exec ns_dev2 ip addr add 10.0.0.2/24 dev veth_dev2_in

# === Transparent Bridges for Bidirectional Traffic Flow ===
ip netns exec ns_dev1 ip link add name br1 type bridge
ip netns exec ns_dev1 ip link set veth_dev1_in  master br1
ip netns exec ns_dev1 ip link set veth_dev1_out master br1
ip netns exec ns_dev1 ip link set br1 up

ip netns exec ns_mitm ip link add name br0 type bridge
ip netns exec ns_mitm ip link set veth_mitm_in  master br0
ip netns exec ns_mitm ip link set veth_mitm_out master br0
ip netns exec ns_mitm ip link set br0 up

ip netns exec ns_dev2 ip link add name br2 type bridge
ip netns exec ns_dev2 ip link set veth_dev2_in  master br2
ip netns exec ns_dev2 ip link set veth_dev2_out master br2
ip netns exec ns_dev2 ip link set br2 up

# promiscuous mode
for dev in veth_dev1_in veth_dev1_out; do
    ip netns exec ns_dev1 ip link set $dev promisc on
done
for dev in veth_dev2_in veth_dev2_out; do
    ip netns exec ns_dev2 ip link set $dev promisc on
done

# MSS clamp (leave room for 16-byte GCM tag)
ip netns exec ns_pc1 iptables -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1440
ip netns exec ns_pc2 iptables -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1440

echo "Environment ready!"
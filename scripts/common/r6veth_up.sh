#!/bin/bash
# r6veth_up.sh: safe veth fixture for host-side R6 injection (L1, root).
# Victim source 172.31.99.2 has a unicast /32 route via a dummy device, so
# source validation passes but SYN-ACKs are dropped by the dummy device
# (no forwarding loop).
set -u
ip link del r6a 2>/dev/null
ip link add r6a type veth peer name r6b
ip addr add 10.99.0.1/24 dev r6b
ip link set r6a up
ip link set r6b up
ip link del dum0 2>/dev/null
ip link add dum0 type dummy
ip link set dum0 up
ip route replace 172.31.99.2/32 dev dum0
ip route del blackhole 172.31.99.0/24 2>/dev/null
sysctl -qw net.ipv4.conf.r6b.rp_filter=0 net.ipv4.conf.r6a.rp_filter=0
sysctl -qw net.ipv4.conf.r6b.forwarding=0 net.ipv4.conf.r6a.forwarding=0
iptables -C FORWARD -i r6a -o r6b -j DROP 2>/dev/null || iptables -I FORWARD 1 -i r6a -o r6b -j DROP
iptables -C FORWARD -i r6b -o r6a -j DROP 2>/dev/null || iptables -I FORWARD 1 -i r6b -o r6a -j DROP
echo "r6veth up: peer=$(cat /sys/class/net/r6b/address) route=$(ip route show 172.31.99.2/32)"

#!/bin/bash
# r7_fixtures.sh -- host-side rt6 probe fixtures for r7 (dev/lab fixture).
# ranges 0x8000..0x80ff: fd01:0:<g>::/64 via fe80::<g> with a FAILED neighbour.
set -u
SLEEP="${1:-12}"
sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null
sysctl -w net.ipv6.conf.virbr-pwn.router_probe_interval=10 >/dev/null 2>&1
sysctl -w net.ipv4.tcp_invalid_ratelimit=0 >/dev/null
sysctl -w net.ipv4.tcp_synack_retries=12 >/dev/null
sysctl -w net.ipv4.tcp_max_syn_backlog=8192 >/dev/null
sysctl -w net.ipv6.neigh.virbr-pwn.gc_thresh1=100000 >/dev/null 2>&1
sysctl -w net.ipv6.neigh.virbr-pwn.gc_thresh2=200000 >/dev/null 2>&1
sysctl -w net.ipv6.neigh.virbr-pwn.gc_thresh3=300000 >/dev/null 2>&1
for g in $(seq $((0x8000)) $((0x80ff))); do
  h=$(printf '%x' $g)
  ip -6 route replace fd01:0:$h::/64 via fe80::$h dev virbr-pwn 2>/dev/null
  ip -6 neigh replace fe80::$h lladdr 02:00:00:00:00:$(printf '%02x' $((g & 0xff))) dev virbr-pwn nud failed 2>/dev/null
done
echo "fixtures 0x8000..0x80ff -> sleeping $SLEEP"
sleep "$SLEEP"
echo "fixtures ready"

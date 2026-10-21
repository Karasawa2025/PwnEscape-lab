#!/bin/bash
# setup_guest: start L2, wait, deploy guest tools, set DROP rules, fixtures.
set -u
L1KEY=/home/ubuntu/.ssh/l2_key
sudo virsh start l2-attacker >/dev/null 2>&1
for i in $(seq 1 90); do
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -i $L1KEY ubuntu@192.168.250.114 "echo up" >/dev/null 2>&1 && break
  sleep 2
done
sudo scp -o StrictHostKeyChecking=no -i $L1KEY /opt/pwnescape/tools/synopt /opt/pwnescape/tools/tcpack /opt/pwnescape/tools/synsniff /opt/pwnescape/tools/genv5.py /opt/pwnescape/tools/poolr.py /opt/pwnescape/tools/v6probe.py /opt/pwnescape/tools/spoofsyn6.py /opt/pwnescape/tools/spoofprobe.py /opt/pwnescape/tools/spoofudp.py /opt/pwnescape/tools/r4.py /opt/pwnescape/tools/d_sendv.py ubuntu@192.168.250.114:/tmp/ >/dev/null 2>&1
ssh -o StrictHostKeyChecking=no -i $L1KEY ubuntu@192.168.250.114 "sudo iptables -C INPUT -p tcp --sport 7778 -j DROP 2>/dev/null || sudo iptables -I INPUT 1 -p tcp --sport 7778 -j DROP; sudo iptables -C INPUT -p tcp --sport 7777 -j DROP 2>/dev/null || sudo iptables -I INPUT 1 -p tcp --sport 7777 -j DROP; ls /tmp/synopt /tmp/genv5.py >/dev/null && echo guest-ready" < /dev/null
sysctl -w net.ipv4.tcp_synack_retries=12 >/dev/null
iptables -t mangle -C INPUT -p tcp --dport 7778 -j CHECKSUM --checksum-fill 2>/dev/null || iptables -t mangle -A INPUT -p tcp --dport 7778 -j CHECKSUM --checksum-fill
for i in all default virbr-pwn vnet0; do sysctl -w net.ipv6.conf.$i.disable_ipv6=0 >/dev/null 2>&1; sysctl -w net.ipv6.conf.$i.accept_dad=0 >/dev/null 2>&1; done
ip -6 addr add fd00:1::1/64 dev virbr-pwn nodad 2>/dev/null
sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null
sysctl -w net.ipv6.conf.virbr-pwn.router_probe_interval=10 >/dev/null 2>&1
for p in $(pgrep -x sshd); do taskset -pc 7 $p >/dev/null 2>&1; done
for t in $(ps -eLo tid,comm | awk '/vhost-/ {print $1}'); do taskset -pc 7 $t >/dev/null 2>&1; done
fuser -k 7778/tcp 2>/dev/null; sleep 0.3
nohup python3 /opt/pwnescape/tools/listen_on.py >/tmp/lst.log 2>&1 &
sleep 0.7
taskset -pc 7 $(pgrep -f listen_on.py) >/dev/null 2>&1
ss -ltn | grep -q ':7778' && echo listener-up

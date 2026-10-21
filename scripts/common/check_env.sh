#!/bin/bash
# check_env.sh -- read-only sanity check for the PwnEscape lab.
# Run as root on L1.
set -u

echo "== kernel =="
uname -r

echo "== target config =="
CFG="/boot/config-$(uname -r)"
if [ -r "$CFG" ]; then
  grep -E 'CONFIG_RANDSTRUCT|CONFIG_DEBUG_OBJECTS|CONFIG_RANDOM_KMALLOC|CONFIG_INIT_ON_ALLOC|CONFIG_FREELIST' "$CFG" || true
else
  echo "no $CFG"
fi

echo "== netfilter writer =="
iptables -t mangle -S INPUT 2>/dev/null | grep -E 'CHECKSUM|7778' || echo "no CHECKSUM mangle rule"
nft list table ip m2 2>/dev/null || echo "no nft table ip m2"

echo "== listener =="
ss -ltn 2>/dev/null | grep ':7778' || echo "no listener on 7778"

echo "== veth fixture =="
ip -br link show r6a 2>/dev/null || true
ip -br link show r6b 2>/dev/null || true
ip -6 addr show dev virbr-pwn 2>/dev/null | grep -E 'fd00:1::1|inet6' || true

echo "== tools =="
for t in /opt/pwnescape/tools/r6obs /opt/pwnescape/tools/r6read.py \
         /opt/pwnescape/tools/r6fire.py /opt/pwnescape/tools/listen_on.py; do
  [ -e "$t" ] && echo "ok $t" || echo "missing $t"
done

echo "== cpu7 kworkers =="
ps -eLo tid,psr,comm | awk '$2==7 && /kworker/ {print}' | head

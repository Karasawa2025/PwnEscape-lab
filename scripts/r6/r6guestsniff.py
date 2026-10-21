#!/usr/bin/env python3
# guest window sniffer: capture the malformed 255-byte-option SYN-ACK.
import socket, struct, time, sys

IFACE = "enp1s0"
SRC = bytes([192, 168, 250, 1])
DST = bytes([192, 168, 250, 114])
out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/guestwin.txt"
secs = int(sys.argv[2]) if len(sys.argv) > 2 else 25

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((IFACE, 0))
s.settimeout(0.5)
deadline = time.time() + secs
with open(out, "w") as f:
    f.write("sniffer up\n"); f.flush()
    while time.time() < deadline:
        try:
            fr = s.recv(65535)
        except socket.timeout:
            continue
        except Exception as e:
            f.write("err %s\n" % e); f.flush(); continue
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
        q0, q1, q2, q3 = struct.unpack("<4Q", win[32:64])
        f.write("GUESTWIN tot=%d dport=%d data=%#x next=%#x prev=%#x func=%#x\n" %
                (struct.unpack(">H", ip[2:4])[0], dport, q0, q1, q2, q3))
        f.write("WINHEX %s\n" % win.hex())
        f.flush()
print("done")

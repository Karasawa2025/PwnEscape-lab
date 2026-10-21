#!/usr/bin/env python3
# cachename.py <kmem_cache_ptr> -> "name idx" (idx 0 for kmalloc-64, NN for kmalloc-rnd-NN-64)
import struct, sys, re

def ksym(n):
    for l in open("/proc/kallsyms"):
        p = l.split()
        if len(p) >= 3 and p[2] == n: return int(p[0], 16)

f = open("/proc/kcore", "rb"); eh = f.read(64)
phoff = struct.unpack_from("<Q", eh, 0x20)[0]; phes = struct.unpack_from("<H", eh, 0x36)[0]; phn = struct.unpack_from("<H", eh, 0x38)[0]
f.seek(phoff); segs = []
for _ in range(phn):
    raw = f.read(phes); t, = struct.unpack_from("<I", raw, 0)
    po, pv, pp, pfz, pmz = struct.unpack_from("<QQQQQ", raw, 8)
    if t == 1: segs.append((po, pv, pfz))
def kr(va, n=8):
    for po, pv, pfz in segs:
        if pv <= va < pv + pfz:
            f.seek(po + (va - pv)); return f.read(n)
    return b""
c = int(sys.argv[1], 16)
nm = struct.unpack("<Q", kr(c + 96, 8))[0]
name = kr(nm, 32).split(b"\x00")[0].decode(errors="replace")
m = re.search(r"rnd-(\d+)", name)
idx = str(int(m.group(1))) if m else ("0" if name == "kmalloc-64" else "?")
print(name, idx)

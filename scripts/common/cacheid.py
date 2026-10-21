import struct,sys,re
def ksym(n):
    for l in open("/proc/kallsyms"):
        p=l.split()
        if len(p)>=3 and p[2]==n: return int(p[0],16)
f=open("/proc/kcore","rb"); eh=f.read(64)
phoff=struct.unpack_from("<Q",eh,0x20)[0]; phes=struct.unpack_from("<H",eh,0x36)[0]; phn=struct.unpack_from("<H",eh,0x38)[0]
f.seek(phoff); segs=[]
for _ in range(phn):
    raw=f.read(phes); t,=struct.unpack_from("<I",raw,0)
    po,pv,pp,pfz,pmz=struct.unpack_from("<QQQQQ",raw,8)
    if t==1: segs.append((po,pv,pfz))
def kr(va,n=8):
    for po,pv,pfz in segs:
        if pv<=va<pv+pfz: f.seek(po+(va-pv)); return f.read(n)
    return b""
pbase=struct.unpack("<Q",kr(ksym("page_offset_base"),8))[0]; vmb=struct.unpack("<Q",kr(ksym("vmemmap_base"),8))[0]
a=int(sys.argv[1],16)
pfn=(a-pbase)>>12; cache=struct.unpack("<Q",kr(vmb+pfn*64+8,8))[0]
nm=struct.unpack("<Q",kr(cache+96,8))[0]
name=kr(nm,32).split(b"\x00")[0].decode(errors="replace")
m=re.search(r"rnd-(\d+)",name)
print(name, m.group(1) if m else "?")

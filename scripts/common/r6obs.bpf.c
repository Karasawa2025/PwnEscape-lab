// r6obs.bpf.c -- CO-RE observer for __rt6_probe_work queue/execute + dopt allocs.
// Replaces the bpftrace oracles used by the R6 host-fixture path.
//
//   raw_tracepoint workqueue_queue_work (linux 6.8 TP_PROTO):
//        args[0] = req_cpu, args[1] = pool_workqueue *, args[2] = work_struct *
//        (the historical 5.x order was work/pwq/req_cpu; this kernel is NOT
//         that order -- verified against include/trace/events/workqueue.h)
//        filter work->func == cfg.target (rt6_probe_deferred)
//        emit QUEUE {work, pwq, data, entry.next/prev, cpu, ts}
//        NB: the tracepoint fires before insert_work(), so data/entry do not
//        exist yet; they are derived (data = pwq|PENDING|PWQ,
//        entry.next = entry.prev = &pool->worklist).
//   raw_tracepoint workqueue_execute_start : args[0] = work
//        emit EXEC {work, func-at-execute, cpu, ts}
//   kprobe __ip_options_echo : arg2 = &dopt->opt (= ip_options_rcu + 16)
//        emit ECHO {dopt, sport, cpu, ts}
//
// Userspace keeps the queued set: QUEUE inserts, EXEC removes.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EV_QUEUE 0
#define EV_EXEC  1
#define EV_ECHO  2

struct ev {
	__u64 ts;
	__u64 work;
	__u64 pwq;
	__u64 data;
	__u64 next;
	__u64 prev;
	__u64 ptr;	/* dopt for ECHO */
	__u64 func;
	__u32 cpu;
	__u32 sport;
	__u32 type;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, __u8);
} tracked SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} cfg SEC(".maps");

static __always_inline void emit(struct ev *e)
{
	bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
}

SEC("raw_tracepoint/workqueue_queue_work")
int tp_queue(struct bpf_raw_tracepoint_args *ctx)
{
	/* TP_PROTO(int req_cpu, struct pool_workqueue *pwq, struct work_struct *work) */
	struct work_struct *w = (struct work_struct *)ctx->args[2];
	void *pwq = (void *)ctx->args[1];
	__u32 k = 0;
	__u64 *tgt = bpf_map_lookup_elem(&cfg, &k);
	__u64 f = 0;
	struct ev e = {};

	if (!w)
		return 0;
	f = (__u64)(unsigned long)BPF_CORE_READ(w, func);
	if (tgt && *tgt && f != *tgt)
		return 0;
	e.ts = bpf_ktime_get_ns();
	e.work = (__u64)w;
	e.pwq = (__u64)pwq;
	{
		struct worker_pool *pool = BPF_CORE_READ((struct pool_workqueue *)pwq, pool);
		/* tracepoint fires before insert_work: data/entry are not yet set.
		 * data = pwq|PENDING|PWQ (extra_flags=0), entry.next/prev = &pool->worklist */
		e.data = (__u64)pwq | 5;
		e.next = (__u64)&pool->worklist;
		e.prev = e.next;
	}
	e.func = f;
	e.cpu = bpf_get_smp_processor_id();
	e.type = EV_QUEUE;
	{
		__u8 one = 1;
		bpf_map_update_elem(&tracked, &e.work, &one, BPF_ANY);
	}
	emit(&e);
	return 0;
}

SEC("raw_tracepoint/workqueue_execute_start")
int tp_exec(struct bpf_raw_tracepoint_args *ctx)
{
	struct ev e = {};
	__u64 w = ctx->args[0];
	__u8 *t = bpf_map_lookup_elem(&tracked, &w);
	if (!t)
		return 0;
	bpf_map_delete_elem(&tracked, &w);

	e.ts = bpf_ktime_get_ns();
	e.work = ctx->args[0];
	e.func = (__u64)(unsigned long)BPF_CORE_READ((struct work_struct *)ctx->args[0], func);
	e.cpu = bpf_get_smp_processor_id();
	e.type = EV_EXEC;
	emit(&e);
	return 0;
}

SEC("kprobe/__ip_options_echo")
int kp_echo(struct pt_regs *ctx)
{
	void *dopt = (void *)PT_REGS_PARM2(ctx);
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	struct ev e = {};
	unsigned char *head;
	__u16 nh, ih;
	__u8 b = 0;
	__u8 sp[2] = {0, 0};

	if (!dopt || !skb)
		return 0;
	head = (unsigned char *)BPF_CORE_READ(skb, head);
	nh = BPF_CORE_READ(skb, network_header);
	ih = BPF_CORE_READ(skb, transport_header);
	if (!head)
		return 0;
	if (bpf_probe_read_kernel(&b, 1, head + nh) != 0)
		return 0;
	/* sport lives at IP header + ihl; transport_header is not reliable for
	 * this path (options were parsed before), so compute from ihl. */
	{
		__u32 off = nh + (__u32)(b & 0x0f) * 4;
		if (bpf_probe_read_kernel(sp, 2, head + off) != 0)
			return 0;
	}
	e.ts = bpf_ktime_get_ns();
	e.ptr = (__u64)dopt;
	e.sport = ((__u32)sp[0] << 8) | sp[1];
	e.cpu = bpf_get_smp_processor_id();
	e.type = EV_ECHO;
	emit(&e);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

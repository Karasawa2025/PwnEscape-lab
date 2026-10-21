// r6obs.c -- userspace loader/decoder for r6obs.bpf.c (libbpf + ringbuf).
// usage: r6obs <target_func_hex> [seconds]
// Prints line-buffered events:
//   QUEUE <work> <pwq> <data> <next> <prev> <func> <cpu> <ts>
//   EXEC  <work> <func_at_execute> <cpu> <ts>
//   ECHO  <dopt> <sport> <cpu> <ts>          (dopt = ip_options_rcu + 16)
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct ev {
	uint64_t ts, work, pwq, data, next, prev, ptr, func;
	uint32_t cpu, sport, type, pad;
};

static volatile int stop;

static void on_sig(int s) { (void)s; stop = 1; }

static int cb(void *ctx, void *data, size_t size)
{
	const struct ev *e = data;
	(void )ctx;
	if (size < sizeof(*e))
		return 0;
	switch (e->type) {
	case 0:
		printf("QUEUE %llx %llx %llx %llx %llx %llx %u %llu\n",
		       (unsigned long long)e->work, (unsigned long long)e->pwq,
		       (unsigned long long)e->data, (unsigned long long)e->next,
		       (unsigned long long)e->prev, (unsigned long long)e->func, e->cpu,
		       (unsigned long long)e->ts);
		break;
	case 1:
		printf("EXEC %llx %llx %u %llu\n", (unsigned long long)e->work,
		       (unsigned long long)e->func, e->cpu, (unsigned long long)e->ts);
		break;
	case 2:
		printf("ECHO %llx %u %u %llu\n", (unsigned long long)e->ptr,
		       e->sport, e->cpu, (unsigned long long)e->ts);
		break;
	}
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *p;
	struct bpf_link *l1, *l2, *l3;
	struct ring_buffer *rb;
	struct bpf_map *cfgmap, *rbmap;
	uint64_t target;
	uint32_t k = 0;
	int secs = 0, err, fd;
	const char *path = getenv("R6OBS_OBJ");
	if (!path)
		path = "/opt/pwnescape/tools/r6obs.bpf.o";
	if (argc < 2) {
		fprintf(stderr, "usage: %s <target_func_hex> [seconds]\n", argv[0]);
		return 1;
	}
	target = strtoull(argv[1], NULL, 16);
	if (argc > 2)
		secs = atoi(argv[2]);
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	obj = bpf_object__open_file(path, NULL);
	if (!obj) {
		fprintf(stderr, "open %s failed: %s\n", path, strerror(errno));
		return 1;
	}
	cfgmap = bpf_object__find_map_by_name(obj, "cfg");
	rbmap = bpf_object__find_map_by_name(obj, "rb");
	if (!cfgmap || !rbmap) {
		fprintf(stderr, "maps not found\n");
		return 1;
	}
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load failed: %s\n", strerror(-err));
		return 1;
	}
	fd = bpf_map__fd(cfgmap);
	if (bpf_map_update_elem(fd, &k, &target, BPF_ANY) != 0) {
		fprintf(stderr, "cfg update2: %s\n", strerror(errno));
		return 1;
	}
	p = bpf_object__find_program_by_name(obj, "tp_queue");
	l1 = p ? bpf_program__attach_raw_tracepoint(p, "workqueue_queue_work") : NULL;
	p = bpf_object__find_program_by_name(obj, "tp_exec");
	l2 = p ? bpf_program__attach_raw_tracepoint(p, "workqueue_execute_start") : NULL;
	p = bpf_object__find_program_by_name(obj, "kp_echo");
	l3 = p ? bpf_program__attach_kprobe(p, false, "__ip_options_echo") : NULL;
	if (!l1 || !l2 || !l3) {
		fprintf(stderr, "attach failed: q=%p e=%p k=%p (%s)\n",
			(void *)l1, (void *)l2, (void *)l3, strerror(errno));
		return 1;
	}
	rb = ring_buffer__new(bpf_map__fd(rbmap), cb, NULL, NULL);
	if (!rb) { fprintf(stderr, "ringbuf new failed\n"); return 1; }
	printf("TARGET %llx READY\n", (unsigned long long)target);
	fflush(stdout);
	while (!stop) {
		err = ring_buffer__poll(rb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "poll: %s\n", strerror(-err));
			break;
		}
		if (secs > 0) {
			static int ms;
			ms += 100;
			if (ms >= secs * 1000)
				break;
		}
	}
	printf("DONE\n");
	fflush(stdout);
	return 0;
}

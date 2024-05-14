#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define path_size 50
#define name_size 10

struct event_start {
	char flag_;
	int pid_;
	char path_[path_size];
	long last_access_time_;
};
struct event_exit {
	char flag_;
	int size_;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_open")
int trace_sys_enter_open(struct trace_event_raw_sys_enter *ctx)
{
	char filename[256];
	int fd = (int)(ctx->args[0].val);
	bpf_probe_read_str(filename, sizeof(filename),
			   (void *)ctx->args[1].val);
	bpf_trace_printk("File Descriptor: %d, File Name: %s\\n", fd, filename);
	return 0;
}

// 将文件中的函数的参数和返回值写入环形缓冲区中，等待用户层读取

SEC("uprobe//libfuse/build/example/fusedemo:dhmp_fs_read")
int read_start(struct pt_regs *ctx)
{
	struct event_start *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}
	e->flag_ = 0;

	int pid = bpf_get_current_pid_tgid() >> 32;
	e->pid_ = pid;

	bpf_probe_read_user_str(e->path_, sizeof(e->path_),
				(void *)PT_REGS_PARM1(ctx));

	u64 t = bpf_ktime_get_ns();
	e->last_access_time_ = t;

	// 向环形缓冲区写入
	bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("uretprobe//libfuse/build/example/fusedemo:dhmp_fs_read")
int read_exit(struct pt_regs *ctx)
{
	struct event_exit *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}
	e->flag_ = 1;
	int ret = PT_REGS_RC(ctx);
	e->size_ = ret;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

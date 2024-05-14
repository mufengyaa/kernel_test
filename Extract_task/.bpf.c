#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define CONFIG_THREAD_INFO_IN_TASK
char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	pid_t ppid;
	char name[30];
	int prio, state, nr_cpus_allowed;
	u64 utime, stime;
	unsigned int policy;
	unsigned exit_code;

	bpf_probe_read_str(name, sizeof(name), task->comm);
	bpf_core_read(&ppid, sizeof(ppid), &task->tgid);
	bpf_core_read(&prio, sizeof(prio), &task->prio);
	bpf_core_read(&utime, sizeof(utime), &task->utime);
	bpf_core_read(&stime, sizeof(stime), &task->stime);
	bpf_core_read(&state, sizeof(state), &task->__state);
	bpf_core_read(&policy, sizeof(policy), &task->policy);
    bpf_core_read(&nr_cpus_allowed, sizeof(nr_cpus_allowed), &task->nr_cpus_allowed);
	exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;

	bpf_printk("PID: %d, PPID: %d, Name: %s,", pid, ppid, name);
	bpf_printk("prio: %d,utime:%lld,stime:%lld,", prio, utime, stime);
	bpf_printk("exit_code:%u,state:%d,policy:%d,", exit_code, state, policy);
	bpf_printk("nr_cpus_allowed:%d\n", nr_cpus_allowed);

	return 0;
}

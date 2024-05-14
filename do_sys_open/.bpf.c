// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL"; //存储了代码的许可证信息

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, pid_t);
// 	__type(value, char[256]);
// 	__uint(max_entries, 1024);
// } my_pid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, char[256]);
	__uint(max_entries, 1024);
} my_pid_map SEC(".maps");

SEC("kprobe/do_sys_open")
int do_sys_open_start(struct pt_regs *ptr)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	//bpf_printk("pid:%d\n", pid);
	char filename[256]; // 假设文件名不超过256字节
	bpf_probe_read_user(filename, sizeof(filename), (void *)ptr->si);

	bpf_map_update_elem(&my_pid_map, &pid, filename, BPF_ANY);

	if (pid == 5527) {
		bpf_printk("%d,do_sys_open success", pid);
	}

	return 0;
}

SEC("kretprobe/do_sys_open")
int do_sys_open_end(struct pt_regs *ptr)
{
	pid_t sp_pid = 5527;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	long ret = (long)(ptr->ax);
	const char *filename; // 假设文件名不超过256字节

	filename = bpf_map_lookup_elem(&my_pid_map, &sp_pid);
	if (pid == sp_pid) {
		bpf_printk("Process ID %d opened file: %s,exit_code: %d\n", pid, filename, ret);
	}

	return 0;
}

// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>

#include "test_kprobe.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "./test_kprobe pid\n");
		return 0;
	}

	struct test_kprobe_bpf *skel;
	int err;
	libbpf_set_print(libbpf_print_fn);

	// int map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "my_pid_map", sizeof(char[256]),
	// 			    sizeof(pid_t), 1024, 0);

	// int ret = bpf_map_update_elem(map_fd, "user", &user_pid, BPF_NOEXIST);
	// if (ret) {
	// 	perror("bpf_map_update_elem");
	// 	exit(EXIT_FAILURE);
	// }

	skel = test_kprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = test_kprobe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");
	//fprintf(stderr, "pid=%d\n", user_pid);

	while (!stop) { //如果没触发sigint信号,就不断打印.
		fprintf(stderr, ".");
		sleep(1);
	}

	// pid_t info = 0;
	// bpf_map_lookup_elem(map_fd, 0, &info);
	// fprintf(stderr, "info=%d\n", info);

cleanup:
	test_kprobe_bpf__destroy(skel);
	return -err;

	// if (argc != 2) {
	// 	fprintf(stderr, "./test_kprobe pid\n");
	// 	return 0;
	// }
	// int user_pid = atoi(argv[1]);
	// struct bpf_object *obj;
	// struct bpf_map *map;
	// int map_fd;

	// // 打开BPF对象文件
	// obj = bpf_object__open_file("./.output/test_kprobe.bpf.o", NULL);
	// if (!obj) {
	// 	fprintf(stderr, "Failed to open BPF object file\n");
	// 	return 1;
	// }

	// // 加载BPF对象
	// if (bpf_object__load(obj)) {
	// 	fprintf(stderr, "Failed to load BPF object file\n");
	// 	bpf_object__close(obj);
	// 	return 1;
	// }
	// struct bpf_program *prog = bpf_object__find_program_by_name(obj, "kprobe_prog");
	// if (!prog) {
	// 	fprintf(stderr, "Failed to find BPF program\n");
	// 	bpf_object__close(obj);
	// 	return 1;
	// }
	// const char *func_name = "do_sys_open";
	// bpf_program__attach_kprobe(prog, BPF_PROBE_ENTRY, func_name)

	// 	// 获取BPF Map
	// 	map = bpf_object__find_map_by_name(obj, "my_pid_map");
	// if (!map) {
	// 	fprintf(stderr, "Failed to find BPF map\n");
	// 	bpf_object__close(obj);
	// 	return 1;
	// }

	// // 获取BPF Map的文件描述符
	// map_fd = bpf_map__fd(map);
	// if (map_fd < 0) {
	// 	fprintf(stderr, "Failed to get BPF map file descriptor\n");
	// 	bpf_object__close(obj);
	// 	return 1;
	// }

	// // 更新BPF Map中键为2的值为100
	// char name[256] = "test.txt";
	// if (bpf_map_update_elem(map_fd, name, &user_pid, BPF_ANY) < 0) {
	// 	fprintf(stderr, "Failed to update element in BPF map\n");
	// 	bpf_object__close(obj);
	// 	return 1;
	// }
	// printf("Updated value for key %s\n", name);

	// if (signal(SIGINT, sig_int) == SIG_ERR) {
	// 	fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
	// }

	// printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	//        "to see output of the BPF programs.\n");

	// while (!stop) { //如果没触发sigint信号,就不断打印.
	// 	fprintf(stderr, ".");
	// 	sleep(1);
	// }
	// // 关闭BPF对象
	// bpf_object__close(obj);
	return 0;
}

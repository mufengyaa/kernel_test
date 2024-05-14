#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>

#include "fuse_metadata.skel.h"
#include "queue.h"

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
struct arg {
	struct queue *start_head_;
	struct queue *exit_head_;
};

struct data_value {
	int pid_;
	int fd_;
	char path_[path_size];
};
struct data_key {
	int pid_;
	int fd_;
};

// 拿每个fd对应的元数据

#define warn(...) fprintf(stderr, __VA_ARGS__)

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct queue *start_head = ((struct arg *)ctx)->start_head_;
	struct queue *exit_head = ((struct arg *)ctx)->exit_head_;

	char *comp = (char *)data;
	if (*comp == 0) { // 入口处
		struct event_start *e = data;
		QueuePush(start_head, e);
	} else {
		struct event_exit *e = data;
		QueuePush(exit_head, e);
	}
	return 0;
}

int main()
{
	struct fuse_metadata_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = fuse_metadata_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	err = fuse_metadata_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	int fd = bpf_map__fd(skel->maps.open_data);

	LIBBPF_OPTS(bpf_uprobe_opts, attach_start_opts,
		    .func_name = "dhmp_fs_read", .retprobe = false);

	struct bpf_link *attach =
		bpf_program__attach_uprobe_opts( // 将 uprobes
						 // 附加到指定的函数上，并传递了设置的选项
			skel->progs.read_start, -1,
			"/libfuse/build/example/fusedemo", 0,
			&attach_start_opts);

	if (!attach) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		err = -1;
		goto cleanup;
	}

	LIBBPF_OPTS(bpf_uprobe_opts, attach_exit_opts,
		    .func_name = "dhmp_fs_read", .retprobe = true);

	attach =
		bpf_program__attach_uprobe_opts( // 将 uprobes
						 // 附加到指定的函数上，并传递了设置的选项
			skel->progs.read_exit, -1,
			"/libfuse/build/example/fusedemo", 0,
			&attach_exit_opts);

	if (!attach) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		err = -1;
		goto cleanup;
	}

	struct queue *start_head = QueueCreate();
	struct queue *exit_head = QueueCreate();
	struct arg *args = MALLOC(struct arg, 1);
	args->exit_head_ = exit_head;
	args->start_head_ = start_head;

	rb = ring_buffer__new(
		bpf_map__fd(skel->maps.rb), handle_event, args,
		NULL); // 创建一个环形缓冲区，并设置好缓冲区的回调函数
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	struct data_key key, *prev_key = NULL;
	struct data_value value;
	while (!exiting) {
		err = bpf_map_get_next_key(
			fd, prev_key,
			&key); // 获取下一个键，当prev=null时，获取第一个键
		if (err) {
			if (errno == ENOENT) { // 没有其他键
				err = 0;
			} else {
				warn("bpf_map_get_next_key failed: %s\n",
				     strerror(errno));
				return err;
			}
		} else {
			err = bpf_map_lookup_elem(fd, &key,
						  &value); // 查找指定键的值
			if (err) {
				warn("bpf_map_lookup_elem failed: %s\n",
				     strerror(errno));
				return err;
			}
			printf("	pid=%d,fd=%d,path=%s\n", value.pid_,
			       value.fd_, value.path_);
			err = bpf_map_delete_elem(fd, &key);
			if (err) {
				warn("bpf_map_delete_elem failed: %s\n",
				     strerror(errno));
				return err;
			}
			prev_key = &key; // 更新prev
		}

		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		struct event_start *start_e = NULL;
		struct event_exit *exit_e = NULL;

		if (!QueueEmpty(start_head)) {
			start_e = (struct event_start *)Queuefront(start_head);
			QueuePop(start_head);
		}
		if (!QueueEmpty(exit_head)) {
			exit_e = (struct event_exit *)Queuefront(exit_head);
			QueuePop(exit_head);
		}

		if (start_e && exit_e) {
			char path[path_size];
			strcpy(path, start_e->path_);
			char filename[name_size];
			int i = 0, j = 0, name_num = 0;
			while (path[i] != '\0') {
				++name_num;
				i++;
			}

			for (i = 0; i < name_num; ++i) {
				if (path[i] == '/') {
					for (j = 0; j < name_num; ++j) {
						filename[j] = path[++i];
					}
					break;
				}
			}

			struct tm *tm;
			char ts[32];
			long t = start_e->last_access_time_;
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);

			int size = exit_e->size_;

			fprintf(stderr,
				"path: %s , filename: %s ,last_access_time_: %8s,size: %d\n",
				path, filename, ts, size);
		}
	}
cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	fuse_metadata_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}

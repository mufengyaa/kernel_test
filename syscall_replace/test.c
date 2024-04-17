#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/unistd.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdint.h>

static long perf_event_open(struct perf_event_attr *attr,
                            pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    pid_t target_pid = atoi(argv[1]);

    // 构造 perf_event_attr 结构体，用于指定要监视的事件类型和配置参数
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_SW_CONTEXT_SWITCHES;

    // 调用 perf_event_open 系统调用，创建性能事件，并将其绑定到目标进程

    printf("Press Enter to stop monitoring.\n");
    while (1)
    {
        int fd = perf_event_open(&pe, target_pid, -1, -1, 0);
        if (fd == -1)
        {
            perror("perf_event_open");
            exit(EXIT_FAILURE);
        }
        uint64_t count;
        int ret = read(fd, &count, sizeof(uint64_t));
        if (ret == -1)
        {
            perror("read");
            exit(EXIT_FAILURE);
        }
        printf("count=%lu\n", count);
        close(fd);
        sleep(1);
        

    }
    getchar(); // 等待用户按下 Enter 键

    // 关闭性能事件

    return 0;
}

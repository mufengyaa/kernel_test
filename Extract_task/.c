#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "test.skel.h"
 
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) 
{
	return vfprintf(stderr, format, args);
}
 
static volatile bool exiting = false;
 
static void sig_handler(int sig)
{
	exiting = true;
}

 
int main(int argc, char **argv)
{
	struct test_bpf *skel;
	int err;
 
	libbpf_set_print(libbpf_print_fn);
 
	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
 
	/* Load and verify BPF application */
	skel = test_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

 
	/* Load & verify BPF programs */
	err = test_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
 
	/* Attach tracepoints */
	err = test_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	while (!exiting){
		printf(".");
        sleep(1);
	}
 
cleanup:
	test_bpf__destroy(skel);
 
	return 0;
}

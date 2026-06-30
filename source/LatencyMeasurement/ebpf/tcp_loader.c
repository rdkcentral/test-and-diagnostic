/*
 * tcp_loader.c - Userspace loader for tcp_hello.bpf.o
 *
 * What it does:
 *   1. Loads tcp_hello.bpf.o into the kernel via libbpf
 *   2. Attaches the sock_ops program to cgroupv2 root
 *      (covers ALL TCP connections on the device)
 *   3. Polls the rtt_counter map every second and prints it
 *
 * Usage:
 *   ./tcp_loader
 *   (tcp_hello.bpf.o must be in the same directory)
 *
 * To stop: Ctrl+C — detaches the BPF program from the cgroup
 *
 * Compile (ARM, via Yocto cross-compiler):
 *   ${CC} ${CFLAGS} ${LDFLAGS} tcp_loader.c \
 *     -I <staging_incdir> -L <staging_libdir> \
 *     -lbpf -lelf -lz -o tcp_loader
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Path to cgroupv2 on this device (confirmed from mount output) */
#define CGROUP_PATH "/sys/fs/cgroup/unified"

/* BPF object file — expected in same directory as the loader */
#define BPF_OBJ_PATH "/usr/bin/ebpf/tcp_hello.bpf.o"

static int prog_fd   = -1;
static int cgroup_fd = -1;

/* Detach cleanly on Ctrl+C */
static void sig_handler(int sig)
{
    (void)sig;
    if (prog_fd >= 0 && cgroup_fd >= 0) {
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_SOCK_OPS);
        printf("\nDetached BPF program from cgroup.\n");
    }
    exit(0);
}

int main(void)
{
    /* ------------------------------------------------------------------ */
    /* 1. Load the BPF object                                              */
    /* ------------------------------------------------------------------ */
    struct bpf_object *obj = bpf_object__open(BPF_OBJ_PATH);
    /* libbpf returns ERR_PTR on failure, not NULL — must use libbpf_get_error() */
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open %s: %ld\n", BPF_OBJ_PATH, libbpf_get_error(obj));
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        return 1;
    }
    printf("BPF program loaded successfully.\n");

    /* ------------------------------------------------------------------ */
    /* 2. Get the program fd                                               */
    /* ------------------------------------------------------------------ */
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "count_rtt");
    if (!prog) {
        fprintf(stderr, "BPF program 'count_rtt' not found in object.\n");
        return 1;
    }
    prog_fd = bpf_program__fd(prog);

    /* ------------------------------------------------------------------ */
    /* 3. Attach to cgroupv2 root — covers all processes on the device    */
    /* ------------------------------------------------------------------ */
    cgroup_fd = open(CGROUP_PATH, O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "Failed to open cgroup at %s: %s\n", CGROUP_PATH, strerror(errno));
        return 1;
    }

    if (bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0)) {
        fprintf(stderr, "Failed to attach BPF program to cgroup: %s\n", strerror(errno));
        return 1;
    }
    printf("Attached to cgroup: %s\n", CGROUP_PATH);
    printf("Open a webpage from a LAN device to generate TCP connections.\n\n");

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* ------------------------------------------------------------------ */
    /* 4. Poll the counter map and print every second                      */
    /* ------------------------------------------------------------------ */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "rtt_counter");
    if (!map) {
        fprintf(stderr, "Map 'rtt_counter' not found.\n");
        return 1;
    }
    int map_fd = bpf_map__fd(map);

    __u32 key = 0;
    __u64 val = 0;
    while (1) {
        if (bpf_map_lookup_elem(map_fd, &key, &val) == 0)
            printf("\rRTT callbacks fired: %llu   ", val);
        else
            printf("\rMap read error: %s", strerror(errno));
        fflush(stdout);
        sleep(1);
    }

    return 0;
}

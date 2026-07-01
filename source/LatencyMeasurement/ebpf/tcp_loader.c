/*
 * tcp_loader.c - Userspace loader for tcp_hello.bpf.o
 *
 * Usage:
 *   ./tcp_loader              # attach to cgroupv2 root (all processes)
 *   ./tcp_loader self         # attach to this process's own cgroup
 *   ./tcp_loader /sys/fs/cgroup/unified/system.slice/...  # specific cgroup
 *
 * To stop: Ctrl+C
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

#define CGROUP_ROOT  "/sys/fs/cgroup/unified"
#define BPF_OBJ_PATH "/usr/bin/ebpf/tcp_hello.bpf.o"

static int  prog_fd   = -1;
static int  cgroup_fd = -1;
static char g_cgroup_path[512];

static void sig_handler(int sig)
{
    (void)sig;
    if (prog_fd >= 0 && cgroup_fd >= 0) {
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_SOCK_OPS);
        printf("\nDetached BPF program from cgroup.\n");
    }
    exit(0);
}

/* Read this process's cgroupv2 path from /proc/self/cgroup */
static int get_self_cgroup_path(char *buf, size_t len)
{
    FILE *f = fopen("/proc/self/cgroup", "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "0::", 3) == 0) {
            char *path = line + 3;
            path[strcspn(path, "\n")] = '\0';
            snprintf(buf, len, "%s%s", CGROUP_ROOT, path);
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

int main(int argc, char *argv[])
{
    /* Resolve cgroup path */
    if (argc < 2 || strcmp(argv[1], "root") == 0) {
        snprintf(g_cgroup_path, sizeof(g_cgroup_path), "%s", CGROUP_ROOT);
    } else if (strcmp(argv[1], "self") == 0) {
        if (get_self_cgroup_path(g_cgroup_path, sizeof(g_cgroup_path)) < 0) {
            fprintf(stderr, "Failed to read own cgroup\n"); return 1;
        }
    } else {
        snprintf(g_cgroup_path, sizeof(g_cgroup_path), "%s", argv[1]);
    }
    printf("Attaching to: %s\n", g_cgroup_path);
    printf("Loader's own cgroup: "); fflush(stdout);
    system("grep '^0::' /proc/self/cgroup");
    printf("\n");
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
    cgroup_fd = open(g_cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "Failed to open cgroup at %s: %s\n", g_cgroup_path, strerror(errno));
        return 1;
    }

    if (bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0)) {
        fprintf(stderr, "Failed to attach BPF program to cgroup: %s\n", strerror(errno));
        return 1;
    }
    printf("Attached successfully. Now run: curl http://example.com\n\n");

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* ------------------------------------------------------------------ */
    /* 4. Poll all diagnostic counters every second                        */
    /* ------------------------------------------------------------------ */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "counters");
    if (!map) {
        fprintf(stderr, "Map 'counters' not found.\n");
        return 1;
    }
    int map_fd = bpf_map__fd(map);

    __u64 val[4] = {0};
    while (1) {
        __u32 k;
        for (k = 0; k < 4; k++)
            bpf_map_lookup_elem(map_fd, &k, &val[k]);
        printf("\r[RTT_CB=%llu] [ACTIVE_ESTAB=%llu] [PASSIVE_ESTAB=%llu] [OTHER=%llu]   ",
               val[0], val[1], val[2], val[3]);
        fflush(stdout);
        sleep(1);
    }

    return 0;
}

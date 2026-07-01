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
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define CGROUP_ROOT  "/sys/fs/cgroup/unified"
#define BPF_OBJ_PATH "/usr/bin/ebpf/tcp_hello.bpf.o"

/* Must match struct conn_key in tcp_hello.bpf.c exactly */
struct conn_key {
    __u32 local_ip6[4];
    __u32 remote_ip6[4];
    __u16 local_port;
    __u16 remote_port;
    __u8  family;
    __u8  pad[3];
};

/* Must match struct rtt_val in tcp_hello.bpf.c exactly */
struct rtt_val {
    __u32 srtt_us;
    __u32 min_rtt_us;
    __u32 max_rtt_us;
    __u32 samples;
};

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

/* Print RTT map — one line per active TCP connection (IPv4 and IPv6) */
static void print_rtt_map(int map_fd)
{
    struct conn_key key = {}, next_key;
    struct rtt_val  val;
    char lip[INET6_ADDRSTRLEN], rip[INET6_ADDRSTRLEN];
    int  found = 0;

    int ret = bpf_map_get_next_key(map_fd, NULL, &key);
    while (ret == 0) {
        if (bpf_map_lookup_elem(map_fd, &key, &val) == 0) {
            int af = (key.family == AF_INET6) ? AF_INET6 : AF_INET;
            inet_ntop(af, key.local_ip6,  lip, sizeof(lip));
            inet_ntop(af, key.remote_ip6, rip, sizeof(rip));
            /* Wrap IPv6 addresses in brackets so port is unambiguous */
            char lfmt[INET6_ADDRSTRLEN + 3], rfmt[INET6_ADDRSTRLEN + 3];
            if (af == AF_INET6) {
                snprintf(lfmt, sizeof(lfmt), "[%s]", lip);
                snprintf(rfmt, sizeof(rfmt), "[%s]", rip);
            } else {
                snprintf(lfmt, sizeof(lfmt), "%s", lip);
                snprintf(rfmt, sizeof(rfmt), "%s", rip);
            }
            printf("  %s:%-5u -> %s:%-5u  "
                   "RTT: %5.2f ms  min: %5.2f ms  max: %5.2f ms  samples: %u\n",
                   lfmt, key.local_port, rfmt, key.remote_port,
                   val.srtt_us    / 1000.0,
                   val.min_rtt_us / 1000.0,
                   val.max_rtt_us / 1000.0,
                   val.samples);
            found++;
        }
        ret = bpf_map_get_next_key(map_fd, &key, &next_key);
        key = next_key;
    }
    if (!found)
        printf("  (no connections seen yet — try: curl http://example.com)\n");
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
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "measure_rtt");
    if (!prog) {
        fprintf(stderr, "BPF program 'measure_rtt' not found in object.\n");
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
    /* 4. Poll the RTT hash map and print per-connection stats             */
    /* ------------------------------------------------------------------ */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "rtt_map");
    if (!map) {
        fprintf(stderr, "Map 'rtt_map' not found.\n");
        return 1;
    }
    int map_fd = bpf_map__fd(map);
    int tick = 0;

    while (1) {
        printf("\n--- tick %d ---\n", ++tick);
        print_rtt_map(map_fd);
        sleep(2);
    }

    return 0;
}

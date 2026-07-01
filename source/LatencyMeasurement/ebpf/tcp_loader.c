/*
 * tcp_loader.c - Userspace loader for tcp_hello.bpf.o (ring buffer edition)
 *
 * Usage:
 *   ./tcp_loader              # attach to cgroupv2 root (all processes)
 *   ./tcp_loader self         # attach to this process's own cgroup
 *   ./tcp_loader /sys/fs/cgroup/unified/system.slice/...  # specific cgroup
 *
 * The BPF program pushes one rtt_event per RTT_CB into a ring buffer.
 * libbpf mmap()s the ring internally; handle_rtt_event() is called
 * for each event without extra syscall overhead per read.
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
#include <pthread.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define CGROUP_ROOT  "/sys/fs/cgroup/unified"
#define BPF_OBJ_PATH "/usr/bin/ebpf/tcp_hello.bpf.o"

/* Must match struct rtt_event in tcp_hello.bpf.c exactly */
struct rtt_event {
    __u32 local_ip6[4];
    __u32 remote_ip6[4];
    __u16 local_port;
    __u16 remote_port;
    __u8  family;
    __u8  pad[3];
    __u32 srtt_us;
};

static int               prog_fd   = -1;
static int               cgroup_fd = -1;
static char              g_cgroup_path[512];
static struct ring_buffer *rb      = NULL;
static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;  /* signal the event loop to exit cleanly */
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

/*
 * Called by ring_buffer__poll() for each event delivered from the kernel.
 * Runs in the same thread as the poll loop — no locking needed.
 */
static int handle_rtt_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data_sz < sizeof(struct rtt_event))
        return 0;

    const struct rtt_event *e = data;
    int af = (e->family == AF_INET6) ? AF_INET6 : AF_INET;

    char lip[INET6_ADDRSTRLEN], rip[INET6_ADDRSTRLEN];
    inet_ntop(af, e->local_ip6,  lip, sizeof(lip));
    inet_ntop(af, e->remote_ip6, rip, sizeof(rip));

    char lfmt[INET6_ADDRSTRLEN + 3], rfmt[INET6_ADDRSTRLEN + 3];
    if (af == AF_INET6) {
        snprintf(lfmt, sizeof(lfmt), "[%s]", lip);
        snprintf(rfmt, sizeof(rfmt), "[%s]", rip);
    } else {
        snprintf(lfmt, sizeof(lfmt), "%s", lip);
        snprintf(rfmt, sizeof(rfmt), "%s", rip);
    }

    printf("  %s:%-5u -> %s:%-5u  RTT: %5.2f ms\n",
           lfmt, e->local_port, rfmt, e->remote_port,
           e->srtt_us / 1000.0);
    fflush(stdout);
    return 0;
}

/*
 * Background thread: drains the ring buffer until running is cleared.
 * handle_rtt_event() is called here for each event — not in main thread.
 */
static void *poll_thread(void *arg)
{
    (void)arg;
    while (running) {
        int n = ring_buffer__poll(rb, 100 /* ms */);
        if (n < 0 && errno != EINTR) {
            fprintf(stderr, "ring_buffer__poll error: %s\n", strerror(errno));
            running = 0;  /* also stop main thread */
            break;
        }
    }
    return NULL;
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
    printf("Attached. Listening for RTT events (Ctrl+C to stop)...\n\n");

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* ------------------------------------------------------------------ */
    /* 4. Create ring buffer consumer                                      */
    /*    libbpf calls mmap() on the map fd to share the ring with kernel  */
    /* ------------------------------------------------------------------ */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "rtt_events");
    if (!map) {
        fprintf(stderr, "Map 'rtt_events' not found.\n");
        return 1;
    }
    int map_fd = bpf_map__fd(map);

    rb = ring_buffer__new(map_fd, handle_rtt_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
        return 1;
    }

    /* ------------------------------------------------------------------ */
    /* 5. Spawn poll thread + hold main via pause()                        */
    /*    poll_thread drains the ring buffer in the background.            */
    /*    pause() suspends main until SIGINT/SIGTERM sets running=0,       */
    /*    at which point the poll thread exits and we join it.             */
    /* ------------------------------------------------------------------ */
    pthread_t poll_tid;
    if (pthread_create(&poll_tid, NULL, poll_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create poll thread: %s\n", strerror(errno));
        return 1;
    }

    while (running)
        pause();  /* sleep until any signal interrupts — then recheck running */

    pthread_join(poll_tid, NULL);

    /* Cleanup runs in normal flow — not inside a signal handler */
    printf("\nDetaching...\n");
    bpf_prog_detach(cgroup_fd, BPF_CGROUP_SOCK_OPS);
    ring_buffer__free(rb);
    bpf_object__close(obj);
    close(cgroup_fd);
    return 0;
}

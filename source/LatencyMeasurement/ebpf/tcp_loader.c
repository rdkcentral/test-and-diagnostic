/*
 * tcp_loader.c - Userspace loader for tcp_hello.bpf.o (TC ring-buffer edition)
 *
 * Usage:
 *   ./tcp_loader              # attach to brlan0 (default LAN bridge)
 *   ./tcp_loader brlan0       # explicit interface name
 *   ./tcp_loader eth1         # any LAN-side interface
 *
 * Attaches the TC BPF program to the named interface as both ingress and
 * egress filters using a clsact qdisc (libbpf TC API).  The BPF program
 * records a timestamp on every TCP SYN (ingress) and emits an rtt_event
 * on every matching TCP SYN-ACK (egress).
 *
 * The resulting RTT is the WAN round-trip time as experienced by each
 * LAN client — measured without the gateway being a TCP endpoint.
 *
 * To stop: Ctrl+C  (detaches both filters and destroys the clsact qdisc)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define DEFAULT_IFACE  "brlan0"
#define BPF_OBJ_PATH   "/usr/bin/ebpf/tcp_hello.bpf.o"

/* Must match struct rtt_event in tcp_hello.bpf.c exactly */
struct rtt_event {
    __u32 client_ip[4];
    __u32 server_ip[4];
    __u16 client_port;
    __u16 server_port;
    __u8  family;
    __u8  pad[3];
    __u32 rtt_us;
};

static struct ring_buffer       *rb      = NULL;
static volatile sig_atomic_t     running = 1;

/* TC hooks and opts saved for cleanup */
static struct bpf_tc_hook  ingress_hook;
static struct bpf_tc_hook  egress_hook;
static struct bpf_tc_opts  ingress_opts;
static struct bpf_tc_opts  egress_opts;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/*
 * Called by ring_buffer__poll() for each RTT event from the kernel.
 * Runs in the poll thread — no locking needed.
 */
static int handle_rtt_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data_sz < sizeof(struct rtt_event))
        return 0;

    const struct rtt_event *e = data;
    int af = (e->family == AF_INET6) ? AF_INET6 : AF_INET;

    char cip[INET6_ADDRSTRLEN], sip[INET6_ADDRSTRLEN];
    inet_ntop(af, e->client_ip, cip, sizeof(cip));
    inet_ntop(af, e->server_ip, sip, sizeof(sip));

    char cfmt[INET6_ADDRSTRLEN + 3], sfmt[INET6_ADDRSTRLEN + 3];
    if (af == AF_INET6) {
        snprintf(cfmt, sizeof(cfmt), "[%s]", cip);
        snprintf(sfmt, sizeof(sfmt), "[%s]", sip);
    } else {
        snprintf(cfmt, sizeof(cfmt), "%s", cip);
        snprintf(sfmt, sizeof(sfmt), "%s", sip);
    }

    printf("  LAN %s:%-5u  ->  WAN %s:%-5u   RTT: %5.2f ms\n",
           cfmt, e->client_port, sfmt, e->server_port,
           e->rtt_us / 1000.0);
    fflush(stdout);
    return 0;
}

/*
 * Background thread: drains the ring buffer until running is cleared.
 */
static void *poll_thread(void *arg)
{
    (void)arg;
    while (running) {
        int n = ring_buffer__poll(rb, 100 /* ms */);
        if (n < 0 && errno != EINTR) {
            fprintf(stderr, "ring_buffer__poll error: %s\n", strerror(errno));
            running = 0;
            break;
        }
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    const char *ifname = (argc >= 2) ? argv[1] : DEFAULT_IFACE;

    /* ------------------------------------------------------------------ */
    /* 0. Resolve interface index                                          */
    /* ------------------------------------------------------------------ */
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Interface '%s' not found: %s\n", ifname, strerror(errno));
        return 1;
    }
    printf("Attaching to interface: %s (ifindex %u)\n", ifname, ifindex);

    /* ------------------------------------------------------------------ */
    /* 1. Load the BPF object                                              */
    /* ------------------------------------------------------------------ */
    struct bpf_object *obj = bpf_object__open(BPF_OBJ_PATH);
    /* libbpf returns ERR_PTR on failure — must use libbpf_get_error() */
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open %s: %ld\n", BPF_OBJ_PATH, libbpf_get_error(obj));
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        return 1;
    }
    printf("BPF program loaded.\n");

    /* ------------------------------------------------------------------ */
    /* 2. Get the TC program fd                                            */
    /* ------------------------------------------------------------------ */
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "measure_rtt_tc");
    if (!prog) {
        fprintf(stderr, "BPF program 'measure_rtt_tc' not found in object.\n");
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    /* ------------------------------------------------------------------ */
    /* 3. Install clsact qdisc + attach to ingress and egress             */
    /*                                                                     */
    /*    ingress: timestamps TCP SYNs from LAN clients                   */
    /*    egress:  on TCP SYN-ACK, computes and emits RTT event           */
    /*                                                                     */
    /*    bpf_tc_hook_create() returns -EEXIST if clsact is already       */
    /*    present — safe to ignore.                                       */
    /* ------------------------------------------------------------------ */
    memset(&ingress_hook, 0, sizeof(ingress_hook));
    ingress_hook.sz           = sizeof(ingress_hook);
    ingress_hook.ifindex      = (int)ifindex;
    ingress_hook.attach_point = BPF_TC_INGRESS;

    int err = bpf_tc_hook_create(&ingress_hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook (ingress): %s\n", strerror(-err));
        return 1;
    }

    memset(&ingress_opts, 0, sizeof(ingress_opts));
    ingress_opts.sz      = sizeof(ingress_opts);
    ingress_opts.prog_fd = prog_fd;
    err = bpf_tc_attach(&ingress_hook, &ingress_opts);
    if (err) {
        fprintf(stderr, "Failed to attach BPF to ingress: %s\n", strerror(-err));
        bpf_tc_hook_destroy(&ingress_hook);
        return 1;
    }

    memset(&egress_hook, 0, sizeof(egress_hook));
    egress_hook.sz           = sizeof(egress_hook);
    egress_hook.ifindex      = (int)ifindex;
    egress_hook.attach_point = BPF_TC_EGRESS;

    /* clsact qdisc is shared — hook_create for egress will return -EEXIST */
    err = bpf_tc_hook_create(&egress_hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook (egress): %s\n", strerror(-err));
        bpf_tc_detach(&ingress_hook, &ingress_opts);
        bpf_tc_hook_destroy(&ingress_hook);
        return 1;
    }

    memset(&egress_opts, 0, sizeof(egress_opts));
    egress_opts.sz      = sizeof(egress_opts);
    egress_opts.prog_fd = prog_fd;
    err = bpf_tc_attach(&egress_hook, &egress_opts);
    if (err) {
        fprintf(stderr, "Failed to attach BPF to egress: %s\n", strerror(-err));
        bpf_tc_detach(&ingress_hook, &ingress_opts);
        bpf_tc_hook_destroy(&ingress_hook);
        return 1;
    }

    printf("TC filters attached (ingress + egress).\n");
    printf("Streaming LAN client RTT events (Ctrl+C to stop)...\n\n");

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* ------------------------------------------------------------------ */
    /* 4. Create ring buffer consumer                                      */
    /*    libbpf mmap()s the ring map so events arrive without per-event  */
    /*    syscall overhead.                                               */
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
    /* 5. Spawn poll thread; main sleeps until SIGINT/SIGTERM             */
    /* ------------------------------------------------------------------ */
    pthread_t poll_tid;
    if (pthread_create(&poll_tid, NULL, poll_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create poll thread: %s\n", strerror(errno));
        return 1;
    }

    while (running)
        pause();  /* woken by signal; recheck running */

    pthread_join(poll_tid, NULL);

    /* ------------------------------------------------------------------ */
    /* 6. Cleanup — runs in normal flow, not inside a signal handler      */
    /*                                                                     */
    /*    Detach individual filters before destroying the qdisc so that   */
    /*    any other TC programs on the interface are not disturbed.       */
    /* ------------------------------------------------------------------ */
    printf("\nDetaching TC filters...\n");
    bpf_tc_detach(&egress_hook,  &egress_opts);
    bpf_tc_detach(&ingress_hook, &ingress_opts);
    /* Destroy the clsact qdisc (ingress_hook ifindex is sufficient) */
    bpf_tc_hook_destroy(&ingress_hook);

    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}

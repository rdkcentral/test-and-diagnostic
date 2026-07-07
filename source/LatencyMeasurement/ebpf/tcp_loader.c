/*
 * tcp_loader.c - Userspace loader for tcp_hello.bpf.o (AF_PACKET socket edition)
 *
 * Usage:
 *   ./tcp_loader              # attach to brlan0 (default LAN bridge)
 *   ./tcp_loader erouter0     # WAN interface (for Broadcom ARCHER platforms)
 *
 * Attaches the BPF program as a socket_filter on an AF_PACKET raw socket.
 * AF_PACKET is the same hook point used by libpcap — it is NOT bypassed by
 * Broadcom ARCHER hardware offload, unlike TC (clsact) hooks.
 *
 * The BPF program timestamps TCP SYNs and emits RTT events to a
 * BPF_MAP_TYPE_ARRAY ring (rtt_events) when SYN-ACKs are matched.
 * The loader is woken via a blocking recv() on the same AF_PACKET
 * socket: the BPF program returns ETH_HLEN only on RTT events, so
 * the socket queues exactly one frame per event — zero polling overhead.
 *
 * To stop: Ctrl+C
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
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <bpf/bpf.h>
#include <sys/socket.h>
#include <netpacket/packet.h>   /* struct sockaddr_ll, struct packet_mreq */

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003        /* all protocols — avoids pulling in kernel UAPI */
#endif

#define DEFAULT_IFACE  "brlan0"
#define BPF_OBJ_PATH   "/usr/bin/ebpf/tcp_hello.bpf.o"

#include "tcp_rtt.h"  /* struct rtt_event (shared with tcp_hello.bpf.c) */

static int                       sock_fd  = -1;  /* AF_PACKET socket */
static int                       rtt_map_fd = -1; /* rtt_events ARRAY map */
static int                       widx_fd  = -1;  /* rtt_write_idx map */
static volatile sig_atomic_t     running  = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/*
 * Suppress libbpf INFO/DEBUG output; only warnings and above are shown.
 */
static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    if (level > LIBBPF_WARN)
        return 0;
    return vfprintf(stderr, format, args);
}

/*
 * Print an RTT event.
 */
static void print_rtt_event(const struct rtt_event *e)
{
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
           e->rtt_ns / 1000000.0);
    fflush(stdout);
}

/*
 * Background thread: polls the rtt_events ARRAY map for new events and
 * logs the BPF diagnostic counters every 5 seconds.
 * Uses bpf_map_update_elem output instead of bpf_perf_event_output because
 * bpf_perf_event_output returns ENOTSUPP for SOCKET_FILTER in softirq on
 * this vendor BCM3390 kernel.
 */
static void *poll_thread(void *arg)
{
    (void)arg;
    __u32 read_cursor = 0;

    while (running) {
        /*
         * Block until the BPF program queues a frame to the socket.
         * BPF returns ETH_HLEN (queuing a wakeup byte) ONLY when it
         * writes an RTT event — so recv() wakes exactly on RTT events,
         * not on every packet.  EINTR means a signal arrived; re-check
         * running and loop.
         */
        char buf[1];
        ssize_t r = recv(sock_fd, buf, sizeof(buf), MSG_TRUNC);
        if (r < 0) {
            /* EINTR = interrupted by signal; EAGAIN/EWOULDBLOCK = SO_RCVTIMEO
             * expired.  Both are normal -- just recheck running and loop. */
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            fprintf(stderr, "recv error: %s\n", strerror(errno));
            running = 0;
            break;
        }

        /* Drain any back-to-back wakeup frames (multiple RTT events) */
        while (recv(sock_fd, buf, sizeof(buf), MSG_DONTWAIT | MSG_TRUNC) > 0) {}

        /* Read all new RTT events written since last wake */
        if (widx_fd >= 0) {
            __u32 widx_key = 0, write_cursor = 0;
            bpf_map_lookup_elem(widx_fd, &widx_key, &write_cursor);
            while (read_cursor != write_cursor) {
                __u32 slot = read_cursor % 32;
                struct rtt_event ev = {};
                if (bpf_map_lookup_elem(rtt_map_fd, &slot, &ev) == 0
                    && ev.rtt_ns > 0)
                    print_rtt_event(&ev);
                read_cursor++;
            }
        }
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    const char *ifname = (argc >= 2) ? argv[1] : DEFAULT_IFACE;

    /* Restrict libbpf output to warnings and errors only. */
    libbpf_set_print(libbpf_print_fn);

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
        int load_errno = errno;
        fprintf(stderr, "Failed to load BPF object: errno=%d (%s)\n",
                load_errno, strerror(load_errno));

        /* Dump every map fd — fd==-1 means that map's creation failed
         * silently, which means THAT map type is the blocker, not the
         * program instructions.                                      */
        fprintf(stderr, "\nMap fd dump (fd==-1 => map creation failed):\n");
        struct bpf_map *m;
        bpf_object__for_each_map(m, obj) {
            fprintf(stderr, "  %-22s  type=%-3d  fd=%d\n",
                    bpf_map__name(m),
                    bpf_map__type(m),
                    bpf_map__fd(m));
        }
        bpf_object__close(obj);
        return 1;
    }
    printf("BPF program loaded.\n");

    /* ------------------------------------------------------------------ */
    /* 2. Get the socket_filter program fd                                 */
    /* ------------------------------------------------------------------ */
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "measure_rtt_tc");
    if (!prog) {
        fprintf(stderr, "BPF program 'measure_rtt_tc' not found in object.\n");
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    /* ------------------------------------------------------------------ */
    /* 3. Create AF_PACKET raw socket and attach BPF socket_filter        */
    /*                                                                     */
    /*    AF_PACKET with SOCK_RAW + ETH_P_ALL delivers all frames         */
    /*    (both TX and RX) to our BPF program.  This is the same hook     */
    /*    point used by libpcap and is visible even on platforms where     */
    /*    hardware offload (e.g. Broadcom ARCHER) bypasses TC hooks.      */
    /* ------------------------------------------------------------------ */
    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        fprintf(stderr, "Failed to create AF_PACKET socket: %s\n", strerror(errno));
        return 1;
    }

    /* Bind to the chosen interface */
    struct sockaddr_ll sll = {};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = (int)ifindex;
    if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "Failed to bind AF_PACKET socket: %s\n", strerror(errno));
        close(sock_fd);
        return 1;
    }

    /* 1-second receive timeout so the poll thread can notice running=0
     * when Ctrl+C sets it.  Without this, recv() blocks forever and
     * pthread_join() hangs. */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Promiscuous mode: ensure we see all frames including those not     */
    /* destined for the gateway's own MAC                                 */
    struct packet_mreq mr = {};
    mr.mr_ifindex = (int)ifindex;
    mr.mr_type    = PACKET_MR_PROMISC;
    if (setsockopt(sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                   &mr, sizeof(mr)) < 0) {
        fprintf(stderr, "Warning: failed to set promiscuous mode: %s\n",
                strerror(errno));  /* non-fatal: we may still see enough traffic */
    }

    /* Attach the BPF socket_filter program */
    if (setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF,
                   &prog_fd, sizeof(prog_fd)) < 0) {
        fprintf(stderr, "Failed to attach BPF to socket: %s\n", strerror(errno));
        close(sock_fd);
        return 1;
    }

    printf("BPF socket_filter attached on %s (AF_PACKET).\n", ifname);
    printf("Streaming LAN client RTT events (Ctrl+C to stop)...\n\n");

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* ------------------------------------------------------------------ */
    /* 4. Open RTT output maps (ARRAY-based, no perf events needed)       */
    /* ------------------------------------------------------------------ */
    struct bpf_map *rtt_map = bpf_object__find_map_by_name(obj, "rtt_events");
    struct bpf_map *widx_map = bpf_object__find_map_by_name(obj, "rtt_write_idx");
    if (!rtt_map || !widx_map) {
        fprintf(stderr, "Map 'rtt_events' or 'rtt_write_idx' not found.\n");
        return 1;
    }
    rtt_map_fd = bpf_map__fd(rtt_map);
    widx_fd    = bpf_map__fd(widx_map);

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
    /* 6. Cleanup                                                          */
    /*    Closing the AF_PACKET socket automatically removes SO_ATTACH_BPF */
    /* ------------------------------------------------------------------ */
    printf("\nDetaching...\n");
    close(sock_fd);   /* removing SO_ATTACH_BPF is automatic on socket close */

    bpf_object__close(obj);
    return 0;
}

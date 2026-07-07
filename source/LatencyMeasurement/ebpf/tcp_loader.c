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
 * The BPF program sees both TX (SYN) and RX (SYN-ACK) frames on the
 * interface, timestamps the SYN, and emits an RTT event on the SYN-ACK
 * via bpf_perf_event_output.
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

/* Must match struct rtt_event in tcp_hello.bpf.c exactly */
struct rtt_event {
    __u32 client_ip[4];
    __u32 server_ip[4];
    __u16 client_port;
    __u16 server_port;
    __u8  family;
    __u8  pad[3];
    __u32 rtt_us;   /* raw nanoseconds (lower 32 bits of SYN→SYN-ACK delta) */
};

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
 * Print all libbpf messages including DEBUG level.
 * DEBUG output shows individual map create / prog load syscalls and
 * lets us see if any map fd comes back as -1 (silent creation failure).
 */
static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    (void)level;   /* print everything: DEBUG, INFO, WARN */
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
           e->rtt_us / 1000000.0);
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
    struct bpf_object *obj = (struct bpf_object *)arg;
    struct bpf_map *cmap = bpf_object__find_map_by_name(obj, "pkt_count");
    int cmap_fd = cmap ? bpf_map__fd(cmap) : -1;
    time_t last_report = time(NULL);
    __u32 read_cursor = 0;  /* next slot to read from */

    while (running) {
        /* Poll the rtt_write_idx to see if BPF wrote any new events */
        if (widx_fd >= 0) {
            __u32 widx_key = 0, write_cursor = 0;
            bpf_map_lookup_elem(widx_fd, &widx_key, &write_cursor);

            while (read_cursor != write_cursor) {
                __u32 slot = read_cursor % 32;
                struct rtt_event ev = {};
                if (bpf_map_lookup_elem(rtt_map_fd, &slot, &ev) == 0
                    && ev.rtt_us > 0)
                    print_rtt_event(&ev);
                read_cursor++;
            }
        }

        usleep(10000);  /* 10 ms poll interval */

        /* Every 5 s: dump BPF packet counter and socket recv queue size */
        if (time(NULL) - last_report >= 5) {
            last_report = time(NULL);
            if (cmap_fd >= 0) {
                __u32 key = 0; __u64 v0=0,v1=0,v2=0,v3=0,v4=0,v5=0,v6=0,v7=0;
                bpf_map_lookup_elem(cmap_fd,&key,&v0); key=1;
                bpf_map_lookup_elem(cmap_fd,&key,&v1); key=2;
                bpf_map_lookup_elem(cmap_fd,&key,&v2); key=3;
                bpf_map_lookup_elem(cmap_fd,&key,&v3); key=4;
                bpf_map_lookup_elem(cmap_fd,&key,&v4); key=5;
                bpf_map_lookup_elem(cmap_fd,&key,&v5); key=6;
                bpf_map_lookup_elem(cmap_fd,&key,&v6); key=7;
                bpf_map_lookup_elem(cmap_fd,&key,&v7);
                fprintf(stderr,
                    "[diag] frames=%llu TCP=%llu SYN=%llu SYN-ACK=%llu "
                    "match_ok=%llu match_fail=%llu perf_ok=%llu perf_errno=%llu(%s)\n",
                    (unsigned long long)v0,(unsigned long long)v1,
                    (unsigned long long)v2,(unsigned long long)v3,
                    (unsigned long long)v4,(unsigned long long)v5,
                    (unsigned long long)v6,(unsigned long long)v7,
                    v7 ? strerror((int)v7) : "none");
                if (v3>0 && v4==0)
                    fprintf(stderr,
                        "       SYN-ACKs seen but NONE matched a stored SYN\n"
                        "       => key mismatch (DNAT not applied yet? different conn?)\n");
                if (v4>0 && v5==0)
                    fprintf(stderr,
                        "       All SYN-ACKs matched — perf_event_output issue\n");
            }
            /* Also drain recv queue and count queued packets */
            int queued = 0;
            char buf[1];
            ssize_t r;
            while ((r = recv(sock_fd, buf, sizeof(buf),
                             MSG_DONTWAIT | MSG_TRUNC)) > 0)
                queued++;
            if (queued)
                fprintf(stderr, "[diag] %d packets drained from socket receive "
                        "queue (BPF returns ETH_HLEN for every frame)\n", queued);
        }
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    const char *ifname = (argc >= 2) ? argv[1] : DEFAULT_IFACE;

    /* Enable full libbpf debug output so every map create and prog load
     * syscall is logged.  This shows exactly where bpf_object__load()
     * fails and whether any map fd comes back as -1.               */
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
    /* 2. Get the TC program fd                                            */
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
    if (pthread_create(&poll_tid, NULL, poll_thread, obj) != 0) {
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
    printf("\nDetaching...\n");
    close(sock_fd);   /* removing SO_ATTACH_BPF is automatic on socket close */

    bpf_object__close(obj);
    return 0;
}

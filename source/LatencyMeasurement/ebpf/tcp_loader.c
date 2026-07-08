/*
 * tcp_loader.c - Userspace loader for tcp_hello.bpf.o (kprobe edition)
 *
 * Usage:
 *   ./tcp_loader              # attach kprobes and stream RTT events
 *
 * Attaches BPF kprobes on ip_forward() (IPv4) and ip6_forward() (IPv6).
 * RTT events are delivered via bpf_perf_event_output (process context)
 * and consumed through the standard perf_buffer API.
 *
 * Advantages over the socket_filter approach:
 *   - No interface-specific binding: all LAN clients covered automatically
 *   - Clean perf_buffer delivery: no ARRAY map ring or recv() wakeup trick
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
#include <arpa/inet.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define BPF_OBJ_PATH   "/usr/bin/ebpf/tcp_hello.bpf.o"

#include "tcp_rtt.h"  /* struct rtt_event (shared with tcp_hello.bpf.c) */

static struct perf_buffer       *pb      = NULL;
static struct bpf_link          *link_v4 = NULL;
static struct bpf_link          *link_v6 = NULL;
static volatile sig_atomic_t     running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/*
 * Suppress libbpf DEBUG output; show INFO and above for initial debugging.
 * Change LIBBPF_INFO to LIBBPF_WARN once kprobe operation is confirmed.
 */
static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    if (level > LIBBPF_DEBUG)  /* show all: WARN + INFO + DEBUG (verifier log) */
        return 0;
    return vfprintf(stderr, format, args);
}

/*
 * perf_buffer callback: called for each RTT event from the kernel.
 */
static void handle_rtt_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    (void)ctx; (void)cpu;
    if (data_sz < sizeof(struct rtt_event))
        return;

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
           e->rtt_ns / 1000000.0);
    fflush(stdout);
}

/*
 * Background thread: polls the perf ring buffer for RTT events.
 * perf_buffer__poll() with a 1-second timeout acts as a natural
 * check on the running flag for Ctrl+C handling.
 */
static void *poll_thread(void *arg)
{
    (void)arg;
    while (running) {
        int n = perf_buffer__poll(pb, 1000 /* ms */);
        if (n < 0 && errno != EINTR) {
            fprintf(stderr, "perf_buffer__poll error: %s\n", strerror(errno));
            running = 0;
            break;
        }

        /* Debug: every 5 s print how many times the kprobes fired.
         * This confirms kprobe attachment is working even if no
         * RTT events appear yet (e.g. wrong SKBUFF_DATA_OFFSET).
         * Remove once operation is confirmed. */
        static time_t last_dbg = 0;
        time_t now = time(NULL);
        if (now - last_dbg >= 5) {
            last_dbg = now;
            struct bpf_object *o = (struct bpf_object *)arg;
            __u64 v[6] = {};
            struct bpf_map *cm = bpf_object__find_map_by_name(o, "dbg_kprobe_count");
            if (cm) {
                int fd = bpf_map__fd(cm);
                __u32 i;
                for (i = 0; i < 6; i++)
                    bpf_map_lookup_elem(fd, &i, &v[i]);
                fprintf(stderr,
                    "[dbg] ip_fwd=%llu ip6_fwd=%llu "
                    "iph_ok=%llu tcp=%llu syn=%llu synack=%llu\n",
                    (unsigned long long)v[0], (unsigned long long)v[1],
                    (unsigned long long)v[2], (unsigned long long)v[3],
                    (unsigned long long)v[4], (unsigned long long)v[5]);
                if (v[0] == 0 && v[1] == 0)
                    fprintf(stderr, "      ip_fwd=0: kprobe not firing\n");
                else if (v[2] == 0)
                    fprintf(stderr, "      iph_ok=0: SKBUFF_DATA_OFFSET=%d wrong\n",
                            204 /* SKBUFF_DATA_OFFSET */);
                else if (v[3] == 0)
                    fprintf(stderr, "      tcp=0: no TCP packets forwarded\n");
                else if (v[4] == 0)
                    fprintf(stderr, "      syn=0: no TCP SYN packets seen\n");
            }

            /* No offset scan map (removed after SKBUFF_DATA_OFFSET=188 confirmed). */
            (void)0;
        }
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    /* Restrict libbpf output to warnings and errors only. */
    libbpf_set_print(libbpf_print_fn);

    /* ------------------------------------------------------------------ */
    /* 0. Probe: can the kernel load ANY BPF_PROG_TYPE_KPROBE program?     */
    /* ------------------------------------------------------------------ */
    {
        /* r0 = 0; exit  -- the simplest valid BPF program */
        struct bpf_insn insns[2] = {
            { .code  = BPF_ALU64 | BPF_MOV | BPF_K,
              .dst_reg = BPF_REG_0, .src_reg = 0,
              .off = 0, .imm = 0 },
            { .code  = BPF_JMP | BPF_EXIT,
              .dst_reg = 0, .src_reg = 0,
              .off = 0, .imm = 0 },
        };
        static char probe_log[4096];
        union bpf_attr attr;
        int pfd;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_KPROBE;
        attr.insns     = (__u64)(uintptr_t)insns;
        attr.insn_cnt  = 2;
        attr.license   = (__u64)(uintptr_t)"GPL";
        attr.log_level = 1;
        attr.log_buf   = (__u64)(uintptr_t)probe_log;
        attr.log_size  = sizeof(probe_log);
        pfd = (int)syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
        if (pfd < 0) {
            fprintf(stderr, "[probe] BPF_PROG_TYPE_KPROBE NOT supported: %s\n",
                    strerror(errno));
            if (probe_log[0])
                fprintf(stderr, "[probe] verifier log:\n%s\n", probe_log);
            else
                fprintf(stderr, "[probe] empty verifier log "
                        "-- program type not registered in kernel\n");
        } else {
            fprintf(stderr, "[probe] BPF_PROG_TYPE_KPROBE supported (fd=%d)"  
                    " -- failure must be in our BPF bytecode\n", pfd);
            if (probe_log[0])
                fprintf(stderr, "[probe] verifier log:\n%s\n", probe_log);
            close(pfd);
        }
    }

    /* ------------------------------------------------------------------ */
    /* 1. Load the BPF object                                              */
    /* ------------------------------------------------------------------ */
    struct bpf_object *obj = bpf_object__open(BPF_OBJ_PATH);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open %s: %ld\n",
                BPF_OBJ_PATH, libbpf_get_error(obj));
        return 1;
    }

    /* Request full verifier log from the kernel for every program so that
     * on load failure the verifier output is captured and printed. */
    {
        struct bpf_program *prog;
        bpf_object__for_each_program(prog, obj)
            bpf_program__set_log_level(prog, 1);
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object: errno=%d (%s)\n",
                errno, strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    printf("BPF programs loaded.\n");

    /* ------------------------------------------------------------------ */
    /* 2. Attach kprobes on ip_forward (IPv4) and ip6_forward (IPv6)      */
    /* ------------------------------------------------------------------ */
    struct bpf_program *prog_v4 =
        bpf_object__find_program_by_name(obj, "kprobe_ip_fwd_v4");
    struct bpf_program *prog_v6 =
        bpf_object__find_program_by_name(obj, "kprobe_ip_fwd_v6");
    if (!prog_v4 || !prog_v6) {
        fprintf(stderr, "BPF programs not found in object.\n");
        bpf_object__close(obj);
        return 1;
    }

    link_v4 = bpf_program__attach_kprobe(prog_v4, false, "ip_forward");
    if (libbpf_get_error(link_v4)) {
        fprintf(stderr, "Failed to attach kprobe/ip_forward: %ld\n",
                libbpf_get_error(link_v4));
        bpf_object__close(obj);
        return 1;
    }

    link_v6 = bpf_program__attach_kprobe(prog_v6, false, "ip6_forward");
    if (libbpf_get_error(link_v6)) {
        fprintf(stderr, "Failed to attach kprobe/ip6_forward: %ld\n",
                libbpf_get_error(link_v6));
        bpf_link__destroy(link_v4);
        bpf_object__close(obj);
        return 1;
    }

    printf("kprobes attached: ip_forward + ip6_forward\n");
    printf("Streaming LAN client RTT events (Ctrl+C to stop)...\n\n");

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* ------------------------------------------------------------------ */
    /* 3. Create perf buffer consumer                                      */
    /* ------------------------------------------------------------------ */
    struct bpf_map *rtt_map = bpf_object__find_map_by_name(obj, "rtt_events");
    if (!rtt_map) {
        fprintf(stderr, "Map 'rtt_events' not found.\n");
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(rtt_map), 64 /* pages per CPU */,
                          handle_rtt_event, NULL, NULL, NULL);
    if (libbpf_get_error(pb)) {
        fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(errno));
        goto cleanup;
    }

    /* ------------------------------------------------------------------ */
    /* 4. Spawn poll thread; main sleeps until SIGINT/SIGTERM             */
    /* ------------------------------------------------------------------ */
    pthread_t poll_tid;
    if (pthread_create(&poll_tid, NULL, poll_thread, obj) != 0) {
        fprintf(stderr, "Failed to create poll thread: %s\n", strerror(errno));
        goto cleanup;
    }

    while (running)
        pause();

    pthread_join(poll_tid, NULL);

cleanup:
    /* ------------------------------------------------------------------ */
    /* 5. Cleanup                                                          */
    /* ------------------------------------------------------------------ */
    printf("\nDetaching kprobes...\n");
    if (pb)        perf_buffer__free(pb);
    if (link_v6)   bpf_link__destroy(link_v6);
    if (link_v4)   bpf_link__destroy(link_v4);
    bpf_object__close(obj);
    return 0;
}


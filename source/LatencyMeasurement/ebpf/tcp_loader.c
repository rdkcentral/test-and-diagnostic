/*
 * If not stated otherwise in this file or this component's Licenses.txt file
 * the following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * tcp_loader.c - Userspace loader for the tcp_hello eBPF kprobe program
 *
 * Usage:
 *   ./tcp_loader              # attach kprobes and stream RTT events
 *
 * Attaches BPF kprobes on ip_forward() (IPv4) and ip6_forward() (IPv6).
 * RTT events are delivered by the BPF program via bpf_ringbuf_output and
 * consumed here through the libbpf ring_buffer API (single shared ring,
 * one epoll fd, no per-CPU split).
 *
 * Advantages over the socket_filter approach:
 *   - No interface-specific binding: all LAN clients covered automatically
 *   - Ring buffer delivery: zero-copy, ordered, no dropped events under load
 *
 * To stop: Ctrl+C or SIGTERM
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
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/*
 * tcp_hello_bpf_o.h is auto-generated from tcp_hello.bpf.o during the build
 * using 'od -v -An -tx1 | awk' to produce a C byte array.  It defines:
 *   static const unsigned char tcp_hello_bpf_o[];   -- BPF ELF bytes
 *   static const unsigned int  tcp_hello_bpf_o_len; -- byte count
 * The loader opens the BPF object directly from memory via
 * bpf_object__open_mem(), so no separate .bpf.o file is needed at runtime.
 * A prebuilt copy lives in prebuilt/tcp_hello_bpf_o.h for platforms without
 * a clang toolchain.
 */
#include "tcp_hello_bpf_o.h"

#include "tcp_rtt.h"  /* struct rtt_event (shared with tcp_hello.bpf.c) */

static struct ring_buffer       *rb      = NULL;
static struct bpf_link          *link_v4 = NULL;
static struct bpf_link          *link_v6 = NULL;
static volatile sig_atomic_t     running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/*
 * libbpf logging: show warnings and errors only.
 */
static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    if (level > LIBBPF_WARN)
        return 0;
    return vfprintf(stderr, format, args);
}

/*
 * ring_buffer callback: called for each RTT event from the kernel.
 * Must return 0 to continue consuming, negative to stop.
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
    printf("  LAN %s:%-5u  ->  WAN %s:%-5u   WAN RTT: %5.2f ms  LAN RTT: %5.2f ms\n",
           cfmt, e->client_port, sfmt, e->server_port,
           e->wan_rtt_ns / 1000000.0,
           e->lan_rtt_ns / 1000000.0);
    fflush(stdout);
    return 0;
}

/*
 * Background thread: polls the ring buffer for RTT events.
 * ring_buffer__poll() blocks in epoll_wait until data arrives or the timeout
 * expires.  The 1-second timeout allows the loop to notice when 'running' is
 * cleared by the signal handler without relying solely on signal delivery.
 * On error ring_buffer__poll() returns -errno; EINTR means a signal arrived
 * (normal shutdown path) so we continue; any other error is fatal.
 */
static void *poll_thread(void *arg)
{
    (void)arg;
    while (running) {
        int n = ring_buffer__poll(rb, 1000 /* ms */);
        if (n < 0) {
            if (n == -EINTR)
                continue;
            fprintf(stderr, "ring_buffer__poll error: %s\n", strerror(-n));
            running = 0;
            break;
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
    /* 1. Load the BPF object from embedded byte array                     */
    /* ------------------------------------------------------------------ */
    struct bpf_object *obj = bpf_object__open_mem(
            tcp_hello_bpf_o, tcp_hello_bpf_o_len, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object from memory: %ld\n",
                libbpf_get_error(obj));
        return 1;
    }

    int load_err = bpf_object__load(obj);
    if (load_err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-load_err));
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
    /* 3. Create ring buffer consumer                                      */
    /* ------------------------------------------------------------------ */
    struct bpf_map *rtt_map = bpf_object__find_map_by_name(obj, "rtt_events");
    if (!rtt_map) {
        fprintf(stderr, "Map 'rtt_events' not found.\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(rtt_map), handle_rtt_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
        goto cleanup;
    }

    /* ------------------------------------------------------------------ */
    /* 4. Spawn poll thread; main sleeps until SIGINT/SIGTERM             */
    /* ------------------------------------------------------------------ */
    pthread_t poll_tid;
    if (pthread_create(&poll_tid, NULL, poll_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create poll thread: %s\n", strerror(errno));
        goto cleanup;
    }

    while (running)
        sleep(1);

    pthread_join(poll_tid, NULL);

cleanup:
    /* ------------------------------------------------------------------ */
    /* 5. Cleanup                                                          */
    /* ------------------------------------------------------------------ */
    printf("\nDetaching kprobes...\n");
    if (rb)        ring_buffer__free(rb);
    if (link_v6)   bpf_link__destroy(link_v6);
    if (link_v4)   bpf_link__destroy(link_v4);
    bpf_object__close(obj);
    return 0;
}


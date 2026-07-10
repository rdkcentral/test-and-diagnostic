/*
 * tcp_hello.bpf.c - eBPF kprobe: LAN-client RTT via TCP handshake timing
 *
 * Attached as kprobes on ip_forward() (IPv4) and ip6_forward() (IPv6).
 * Both SYN (LAN->WAN) and SYN-ACK (WAN->LAN) pass through these functions
 * for every forwarded packet -- no interface binding needed.
 *
 * Advantages over the socket_filter approach:
 *   - bpf_perf_event_output works (kprobes run in process context, not softirq)
 *   - Interface-agnostic: all LAN clients on all ports are covered automatically
 *   - No AF_PACKET socket or recv() wakeup trick needed
 *
 * How it works
 * -------------
 *   TCP SYN  : store flow_key -> ktime_ns in syn_timestamps LRU hash map.
 *   TCP SYN-ACK: reverse key, look up SYN timestamp, compute RTT,
 *                emit rtt_event via bpf_perf_event_output.
 *
 * sk_buff->data offset
 * ---------------------
 *   Without BTF/CO-RE, skb->data is accessed at a hardcoded byte offset
 *   (SKBUFF_DATA_OFFSET).  Verify with:
 *     pahole -C sk_buff <kernel_vmlinux> | grep " data;"
 *   Safe failure mode: wrong offset -> bpf_probe_read_kernel() returns error
 *   -> no RTT events, no crash.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * ARM32: struct pt_regs must be fully defined before bpf_tracing.h so that
 * the BPF_KPROBE / PT_REGS_PARMn macros can access uregs[].  With
 * "-target bpf" the arch-specific ptrace.h is not included automatically.
 */
#ifndef __ASSEMBLY__
struct pt_regs {
    unsigned long uregs[18];
};
#endif

#include <bpf/bpf_tracing.h>   /* BPF_KPROBE, PT_REGS_PARM1 */
#include "tcp_rtt.h"            /* struct rtt_event (shared with tcp_loader.c) */
#include "bpf_net_defs.h"       /* iphdr, ipv6hdr, tcphdr, flow_key, TCP_FLAG_* */
#include "skbuff_offset.h"      /* SKBUFF_DATA_OFFSET (config-computed) */

/*
 * Global forward declaration so BPF_KPROBE's two macro expansions (forward
 * declaration + definition) both refer to the same struct tag.  Without this,
 * each prototype scope creates its own 'struct sk_buff', causing a
 * "conflicting types" error.
 */
struct sk_buff;

/*
 * Hash map: in-flight SYN flows -> arrival timestamp (nanoseconds).
 * LRU so oldest entries are evicted instead of blocking new insertions.
 */
struct bpf_map_def SEC("maps") syn_timestamps = {
    .type        = BPF_MAP_TYPE_LRU_HASH,
    .key_size    = sizeof(struct flow_key),
    .value_size  = sizeof(__u64),
    .max_entries = 8192,
};

/*
 * Intermediate state stored when SYN-ACK is seen, keyed by the canonical
 * (client→server) flow key.  Consumed when the subsequent ACK arrives to
 * compute LAN latency (SYN-ACK → ACK).
 * Max age: if ACK does not arrive within MAX_SYNACK_AGE_NS the entry is
 * ignored (evicted by LRU or stale-detected at ACK time).
 */
#define MAX_SYNACK_AGE_NS (5ULL * 1000000000ULL)  /* 5 seconds */

struct synack_state {
    __u32 client_ip[4];
    __u32 server_ip[4];
    __u16 client_port;
    __u16 server_port;
    __u8  family;
    __u8  pad[3];
    __u64 synack_time_ns;  /* ktime when SYN-ACK was forwarded */
    __u32 wan_rtt_ns;      /* SYN → SYN-ACK already computed */
};

struct bpf_map_def SEC("maps") synack_states = {
    .type        = BPF_MAP_TYPE_LRU_HASH,
    .key_size    = sizeof(struct flow_key),
    .value_size  = sizeof(struct synack_state),
    .max_entries = 8192,
};

/*
 * Ring buffer: delivers rtt_event structs to userspace.
 * Single shared ring (no per-CPU split), one fd in epoll.
 * bpf_ringbuf_output works for kprobe programs (process context).
 */
struct bpf_map_def SEC("maps") rtt_events = {
    .type        = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 256 * 1024,  /* 256 KB ring; power-of-2, multiple of page size */
};

/* ---- IPv4 forwarding kprobe -------------------------------------------- */

static __always_inline int handle_v4(const void *data)
{
    struct iphdr iph;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), data))
        return 0;
    if (iph.protocol != IPPROTO_TCP)
        return 0;

    __u32 ihl = iph.ihl * 4;
    if (ihl < 20)
        return 0;

    struct tcphdr tcph;
    if (bpf_probe_read_kernel(&tcph, sizeof(tcph), data + ihl))
        return 0;

    struct flow_key key = {};
    key.family    = AF_INET;
    key.src_ip[0] = iph.saddr;
    key.dst_ip[0] = iph.daddr;
    key.src_port  = bpf_ntohs(tcph.source);
    key.dst_port  = bpf_ntohs(tcph.dest);

    /* SYN only (no ACK/RST/FIN) */
    if (tcph.syn && !tcph.ack && !tcph.rst && !tcph.fin) {
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&syn_timestamps, &key, &ts, BPF_ANY);

    } else if (tcph.syn && tcph.ack && !tcph.rst && !tcph.fin) {  /* SYN-ACK */
        struct flow_key syn_key = {};
        syn_key.family   = key.family;
        __builtin_memcpy(syn_key.src_ip, key.dst_ip, sizeof(syn_key.src_ip));
        __builtin_memcpy(syn_key.dst_ip, key.src_ip, sizeof(syn_key.dst_ip));
        syn_key.src_port = key.dst_port;
        syn_key.dst_port = key.src_port;

        __u64 *syn_ts = bpf_map_lookup_elem(&syn_timestamps, &syn_key);
        if (syn_ts) {
            __u64 now       = bpf_ktime_get_ns();
            __u32 wan_rtt   = (__u32)(now - *syn_ts);
            bpf_map_delete_elem(&syn_timestamps, &syn_key);

            /* Store state for ACK matching */
            struct synack_state sa = {};
            sa.family         = AF_INET;
            __builtin_memcpy(sa.client_ip, key.dst_ip, sizeof(sa.client_ip));
            sa.client_port    = key.dst_port;
            __builtin_memcpy(sa.server_ip, key.src_ip, sizeof(sa.server_ip));
            sa.server_port    = key.src_port;
            sa.synack_time_ns = now;
            sa.wan_rtt_ns     = wan_rtt;
            bpf_map_update_elem(&synack_states, &syn_key, &sa, BPF_ANY);
        }

    } else if (!tcph.syn && tcph.ack && !tcph.rst && !tcph.fin) {  /* ACK */
        /* Match against a pending synack_state (connection-setup ACK only;
         * data-transfer ACKs will find no entry and return quickly). */
        struct synack_state *sa = bpf_map_lookup_elem(&synack_states, &key);
        if (sa && (bpf_ktime_get_ns() - sa->synack_time_ns) < MAX_SYNACK_AGE_NS) {
            __u32 lan_rtt = (__u32)(bpf_ktime_get_ns() - sa->synack_time_ns);
            bpf_map_delete_elem(&synack_states, &key);

            struct rtt_event ev = {};
            ev.family      = AF_INET;
            __builtin_memcpy(ev.client_ip, sa->client_ip, sizeof(ev.client_ip));
            ev.client_port = sa->client_port;
            __builtin_memcpy(ev.server_ip, sa->server_ip, sizeof(ev.server_ip));
            ev.server_port = sa->server_port;
            ev.wan_rtt_ns  = sa->wan_rtt_ns;
            ev.lan_rtt_ns  = lan_rtt;
            bpf_ringbuf_output(&rtt_events, &ev, sizeof(ev), 0);
        }
    }
    return 0;
}

SEC("kprobe/ip_forward")
int BPF_KPROBE(kprobe_ip_fwd_v4, struct sk_buff *skb)
{
    void *data;
    if (bpf_probe_read_kernel(&data, sizeof(data),
                               (const char *)skb + SKBUFF_DATA_OFFSET))
        return 0;
    if (!data)
        return 0;
    return handle_v4(data);
}

/* ---- IPv6 forwarding kprobe -------------------------------------------- */

static __always_inline int handle_v6(const void *data)
{
    struct ipv6hdr ip6h;
    if (bpf_probe_read_kernel(&ip6h, sizeof(ip6h), data))
        return 0;
    if (ip6h.nexthdr != IPPROTO_TCP)
        return 0;

    struct tcphdr tcph;
    if (bpf_probe_read_kernel(&tcph, sizeof(tcph), data + sizeof(ip6h)))
        return 0;

    struct flow_key key = {};
    key.family = AF_INET6;
    __builtin_memcpy(key.src_ip, &ip6h.saddr, 16);
    __builtin_memcpy(key.dst_ip, &ip6h.daddr, 16);
    key.src_port = bpf_ntohs(tcph.source);
    key.dst_port = bpf_ntohs(tcph.dest);

    if (tcph.syn && !tcph.ack && !tcph.rst && !tcph.fin) {
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&syn_timestamps, &key, &ts, BPF_ANY);

    } else if (tcph.syn && tcph.ack && !tcph.rst && !tcph.fin) {  /* SYN-ACK */
        struct flow_key syn_key = {};
        syn_key.family   = key.family;
        __builtin_memcpy(syn_key.src_ip, key.dst_ip, sizeof(syn_key.src_ip));
        __builtin_memcpy(syn_key.dst_ip, key.src_ip, sizeof(syn_key.dst_ip));
        syn_key.src_port = key.dst_port;
        syn_key.dst_port = key.src_port;

        __u64 *syn_ts = bpf_map_lookup_elem(&syn_timestamps, &syn_key);
        if (syn_ts) {
            __u64 now     = bpf_ktime_get_ns();
            __u32 wan_rtt = (__u32)(now - *syn_ts);
            bpf_map_delete_elem(&syn_timestamps, &syn_key);

            struct synack_state sa = {};
            sa.family         = AF_INET6;
            __builtin_memcpy(sa.client_ip, key.dst_ip, sizeof(sa.client_ip));
            sa.client_port    = key.dst_port;
            __builtin_memcpy(sa.server_ip, key.src_ip, sizeof(sa.server_ip));
            sa.server_port    = key.src_port;
            sa.synack_time_ns = now;
            sa.wan_rtt_ns     = wan_rtt;
            bpf_map_update_elem(&synack_states, &syn_key, &sa, BPF_ANY);
        }

    } else if (!tcph.syn && tcph.ack && !tcph.rst && !tcph.fin) {  /* ACK */
        struct synack_state *sa = bpf_map_lookup_elem(&synack_states, &key);
        if (sa && (bpf_ktime_get_ns() - sa->synack_time_ns) < MAX_SYNACK_AGE_NS) {
            __u32 lan_rtt = (__u32)(bpf_ktime_get_ns() - sa->synack_time_ns);
            bpf_map_delete_elem(&synack_states, &key);

            struct rtt_event ev = {};
            ev.family      = AF_INET6;
            __builtin_memcpy(ev.client_ip, sa->client_ip, sizeof(ev.client_ip));
            ev.client_port = sa->client_port;
            __builtin_memcpy(ev.server_ip, sa->server_ip, sizeof(ev.server_ip));
            ev.server_port = sa->server_port;
            ev.wan_rtt_ns  = sa->wan_rtt_ns;
            ev.lan_rtt_ns  = lan_rtt;
            bpf_ringbuf_output(&rtt_events, &ev, sizeof(ev), 0);
        }
    }
    return 0;
}

SEC("kprobe/ip6_forward")
int BPF_KPROBE(kprobe_ip_fwd_v6, struct sk_buff *skb)
{
    void *data;
    if (bpf_probe_read_kernel(&data, sizeof(data),
                               (const char *)skb + SKBUFF_DATA_OFFSET))
        return 0;
    if (!data)
        return 0;
    return handle_v6(data);
}

char _license[] SEC("license") = "GPL";

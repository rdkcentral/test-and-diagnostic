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

/*
 * Global forward declaration so BPF_KPROBE's two macro expansions (forward
 * declaration + definition) both refer to the same struct tag.  Without this,
 * each prototype scope creates its own 'struct sk_buff', causing a
 * "conflicting types" error.
 */
struct sk_buff;

#define AF_INET   2
#define AF_INET6  10
#define IPPROTO_TCP 6

/*
 * Byte offset of the 'data' pointer field inside struct sk_buff.
 * This BCM3390/RDKB vendor kernel (Linux 5.15 ARM32) has extra fields
 * beyond mainline that push 'data' to offset 188:
 *
 *   +0    next, prev, dev          (12)
 *   +12   sk                       ( 4)
 *   +16   tstamp                   ( 8)
 *   +24   cb[48]                   (48)
 *   +72   _skb_refdst, destructor  ( 8)
 *   +80   _nfct (NF_CONNTRACK)     ( 4)
 *   +84   dev_in (BCM NF_OFFLOAD)  ( 4)  BCM_KF_CM + NF_CONNTRACK_OFFLOAD
 *   +88   len, data_len            ( 8)
 *   +96   mac_len, hdr_len         ( 4)
 *   +100  queue_mapping            ( 2)
 *   +102  cloned/active_ext bytes  ( 2)
 *   +104  bitfields (pkt_type etc) ( 6)  includes BCM recycle+flooded bits
 *   +110  tc_index (NET_SCHED)     ( 2)
 *   +112  csum                     ( 4)
 *   +116  priority                 ( 4)
 *   +120  skb_iif                  ( 4)
 *   +124  hash                     ( 4)
 *   +128  vlan_proto, vlan_tci     ( 4)
 *   +132  napi_id (NET_RX_BUSY)    ( 4)  CONFIG_NET_RX_BUSY_POLL=y
 *   +136  mark                     ( 4)  no secmark (NETWORK_SECMARK=n)
 *   +140  inner_protocol+inner headers+proto/transport/network/mac (16)
 *   +156  [pad to 4-byte align]    ( 4)
 *   +160  recycle (BCM SKB_RECYCLE)( 4)
 *   +164  recycle_arg              ( 4)
 *   +168  recycle_shinfo           ( 4)
 *   +172  [pad to 8-byte align]    ( 4)  for tail pointer
 *   +176  tail                     ( 4)  (ANDROID_KABI_RESERVE=n: 0 bytes)
 *   +180  end                      ( 4)
 *   +184  head                     ( 4)
 *   +188  data  <-- confirmed by offset scan (offset 188: hits matched ip_fwd count)
 */
#define SKBUFF_DATA_OFFSET  188

/*
 * Custom struct definitions for iphdr, ipv6hdr, and tcphdr.
 * Standard kernel headers use bitfields whose layout is ambiguous for
 * clang -target bpf.  Plain bytes/shorts are correct regardless of
 * byte order and avoid that entire class of bug.
 */
struct iphdr {
    __u8  ihl_version;   /* high nibble = version, low nibble = IHL */
    __u8  tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;         /* network byte order */
    __u32 daddr;
} __attribute__((packed));

struct ipv6hdr {
    __u8  version_prio;  /* high nibble = version */
    __u8  flow_lbl[3];
    __u16 payload_len;
    __u8  nexthdr;
    __u8  hop_limit;
    __u8  saddr[16];     /* network byte order */
    __u8  daddr[16];
} __attribute__((packed));

struct tcphdr {
    __u16 source;        /* network byte order */
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u8  doff_res;      /* high nibble = data offset */
    __u8  flags;         /* bit0=FIN bit1=SYN bit2=RST bit3=PSH bit4=ACK */
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
} __attribute__((packed));

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_ACK 0x10

/*
 * Five-tuple key: matches a SYN with its returning SYN-ACK.
 */
struct flow_key {
    __u32 src_ip[4];  /* AF_INET: [0]=addr, [1-3]=0  AF_INET6: full 128-bit */
    __u32 dst_ip[4];  /* network byte order */
    __u16 src_port;   /* host byte order */
    __u16 dst_port;
    __u8  family;     /* AF_INET or AF_INET6 */
    __u8  pad[3];
};

/*
 * Debug counter: incremented every time ip_forward/ip6_forward fires.
 * Check via tcp_loader's 5-second diag output.
 * Remove once kprobe operation is confirmed.
 */
struct bpf_map_def SEC("maps") dbg_kprobe_count = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u64),
    .max_entries = 6,  /* [0]=ip_fwd [1]=ip6_fwd [2]=iph_ok [3]=tcp [4]=syn [5]=synack */
};

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
 * Perf event array: delivers rtt_event structs to userspace.
 * bpf_perf_event_output works for kprobe programs (process context).
 */
struct bpf_map_def SEC("maps") rtt_events = {
    .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 128,
};

/* ---- IPv4 forwarding kprobe -------------------------------------------- */

static __always_inline int handle_v4(struct pt_regs *ctx, const void *data)
{
    struct iphdr iph;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), data))
        return 0;
    /* [2] skb->data was readable: SKBUFF_DATA_OFFSET is correct */
    { __u32 _k = 2; __u64 *_c = bpf_map_lookup_elem(&dbg_kprobe_count, &_k); if (_c) *_c = *_c + 1; }
    if (iph.protocol != IPPROTO_TCP)
        return 0;
    /* [3] TCP packet */
    { __u32 _k = 3; __u64 *_c = bpf_map_lookup_elem(&dbg_kprobe_count, &_k); if (_c) *_c = *_c + 1; }

    __u32 ihl = (iph.ihl_version & 0x0F) * 4;
    if (ihl < 20)
        return 0;

    struct tcphdr tcph;
    if (bpf_probe_read_kernel(&tcph, sizeof(tcph), data + ihl))
        return 0;

    __u8 ctl = tcph.flags &
               (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN);

    struct flow_key key = {};
    key.family    = AF_INET;
    key.src_ip[0] = iph.saddr;
    key.dst_ip[0] = iph.daddr;
    key.src_port  = bpf_ntohs(tcph.source);
    key.dst_port  = bpf_ntohs(tcph.dest);

    if (ctl == TCP_FLAG_SYN) {
        /* [4] SYN */
        { __u32 _k = 4; __u64 *_c = bpf_map_lookup_elem(&dbg_kprobe_count, &_k); if (_c) *_c = *_c + 1; }
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&syn_timestamps, &key, &ts, BPF_ANY);

    } else if (ctl == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
        /* [5] SYN-ACK */
        { __u32 _k = 5; __u64 *_c = bpf_map_lookup_elem(&dbg_kprobe_count, &_k); if (_c) *_c = *_c + 1; }
        struct flow_key syn_key = {};
        syn_key.family   = key.family;
        __builtin_memcpy(syn_key.src_ip, key.dst_ip, sizeof(syn_key.src_ip));
        __builtin_memcpy(syn_key.dst_ip, key.src_ip, sizeof(syn_key.dst_ip));
        syn_key.src_port = key.dst_port;
        syn_key.dst_port = key.src_port;

        __u64 *syn_ts = bpf_map_lookup_elem(&syn_timestamps, &syn_key);
        if (syn_ts) {
            __u64 rtt_ns = bpf_ktime_get_ns() - *syn_ts;
            bpf_map_delete_elem(&syn_timestamps, &syn_key);

            struct rtt_event ev = {};
            ev.family      = AF_INET;
            __builtin_memcpy(ev.client_ip, key.dst_ip, sizeof(ev.client_ip));
            ev.client_port = key.dst_port;
            __builtin_memcpy(ev.server_ip, key.src_ip, sizeof(ev.server_ip));
            ev.server_port = key.src_port;
            ev.rtt_ns      = (__u32)rtt_ns;
            bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU,
                                  &ev, sizeof(ev));
        }
    }
    return 0;
}

SEC("kprobe/ip_forward")
int BPF_KPROBE(kprobe_ip_fwd_v4, struct sk_buff *skb)
{
    /* debug: count every ip_forward() invocation */
    __u32 k = 0; __u64 *c = bpf_map_lookup_elem(&dbg_kprobe_count, &k);
    if (c) *c = *c + 1;

    void *data;
    if (bpf_probe_read_kernel(&data, sizeof(data),
                               (const char *)skb + SKBUFF_DATA_OFFSET))
        return 0;
    if (!data)
        return 0;
    return handle_v4(ctx, data);
}

/* ---- IPv6 forwarding kprobe -------------------------------------------- */

static __always_inline int handle_v6(struct pt_regs *ctx, const void *data)
{
    struct ipv6hdr ip6h;
    if (bpf_probe_read_kernel(&ip6h, sizeof(ip6h), data))
        return 0;
    if (ip6h.nexthdr != IPPROTO_TCP)
        return 0;

    struct tcphdr tcph;
    if (bpf_probe_read_kernel(&tcph, sizeof(tcph), data + sizeof(ip6h)))
        return 0;

    __u8 ctl = tcph.flags &
               (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN);

    struct flow_key key = {};
    key.family = AF_INET6;
    __builtin_memcpy(key.src_ip, ip6h.saddr, 16);
    __builtin_memcpy(key.dst_ip, ip6h.daddr, 16);
    key.src_port = bpf_ntohs(tcph.source);
    key.dst_port = bpf_ntohs(tcph.dest);

    if (ctl == TCP_FLAG_SYN) {
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&syn_timestamps, &key, &ts, BPF_ANY);

    } else if (ctl == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
        struct flow_key syn_key = {};
        syn_key.family   = key.family;
        __builtin_memcpy(syn_key.src_ip, key.dst_ip, sizeof(syn_key.src_ip));
        __builtin_memcpy(syn_key.dst_ip, key.src_ip, sizeof(syn_key.dst_ip));
        syn_key.src_port = key.dst_port;
        syn_key.dst_port = key.src_port;

        __u64 *syn_ts = bpf_map_lookup_elem(&syn_timestamps, &syn_key);
        if (syn_ts) {
            __u64 rtt_ns = bpf_ktime_get_ns() - *syn_ts;
            bpf_map_delete_elem(&syn_timestamps, &syn_key);

            struct rtt_event ev = {};
            ev.family = AF_INET6;
            __builtin_memcpy(ev.client_ip, key.dst_ip, sizeof(ev.client_ip));
            ev.client_port = key.dst_port;
            __builtin_memcpy(ev.server_ip, key.src_ip, sizeof(ev.server_ip));
            ev.server_port = key.src_port;
            ev.rtt_ns = (__u32)rtt_ns;
            bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU,
                                  &ev, sizeof(ev));
        }
    }
    return 0;
}

SEC("kprobe/ip6_forward")
int BPF_KPROBE(kprobe_ip_fwd_v6, struct sk_buff *skb)
{
    /* debug: count every ip6_forward() invocation */
    __u32 k = 1; __u64 *c = bpf_map_lookup_elem(&dbg_kprobe_count, &k);
    if (c) *c = *c + 1;

    void *data;
    if (bpf_probe_read_kernel(&data, sizeof(data),
                               (const char *)skb + SKBUFF_DATA_OFFSET))
        return 0;
    if (!data)
        return 0;
    return handle_v6(ctx, data);
}

char _license[] SEC("license") = "GPL";

/*
 * tcp_hello.bpf.c - eBPF TC program: LAN-client RTT via TCP handshake timing
 *
 * Attach to the LAN bridge interface (e.g. brlan0) as both ingress and
 * egress TC filters using the same compiled object:
 *
 *   tc qdisc  add dev brlan0 clsact
 *   tc filter add dev brlan0 ingress bpf obj tcp_hello.bpf.o sec tc da
 *   tc filter add dev brlan0 egress  bpf obj tcp_hello.bpf.o sec tc da
 *
 * (tcp_loader handles all of the above automatically.)
 *
 * How it works
 * ─────────────
 *   ingress (packet FROM LAN client → WAN):
 *     TCP SYN  →  store flow_key → ktime_ns in syn_timestamps hash map
 *
 *   egress (packet TO LAN client ← WAN):
 *     TCP SYN-ACK → reverse the flow key, look up the SYN timestamp,
 *                   compute RTT = now − SYN_ts, emit rtt_event to ring buffer
 *
 * The SYN→SYN-ACK delta is the WAN RTT as experienced by the LAN client.
 *
 * Stale SYN entries (no SYN-ACK ever arrives) are evicted automatically
 * by the LRU hash map once it reaches max_entries.
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET  2
#define AF_INET6 10

/*
 * Five-tuple key used to match a SYN with its returning SYN-ACK.
 * family + pad keep the struct at a round size (40 bytes).
 */
struct flow_key {
    __u32 src_ip[4];   /* AF_INET: [0]=addr, [1-3]=0   AF_INET6: full 128-bit */
    __u32 dst_ip[4];   /* network byte order                                   */
    __u16 src_port;    /* host byte order */
    __u16 dst_port;
    __u8  family;      /* AF_INET or AF_INET6 */
    __u8  pad[3];
};

/*
 * RTT event pushed to the userspace ring buffer.
 * client_* = LAN-side host;  server_* = WAN-side peer.
 */
struct rtt_event {
    __u32 client_ip[4];
    __u32 server_ip[4];
    __u16 client_port;  /* host byte order */
    __u16 server_port;
    __u8  family;       /* AF_INET or AF_INET6 */
    __u8  pad[3];
    __u32 rtt_us;       /* RTT in microseconds (SYN → SYN-ACK) */
};

/*
 * Hash map: in-flight SYN flows → arrival timestamp (nanoseconds).
 * LRU type so oldest entries are evicted under SYN-flood conditions
 * instead of blocking new insertions.
 * Legacy map definition (no BTF) for compatibility without CONFIG_DEBUG_INFO_BTF.
 */
struct bpf_map_def SEC("maps") syn_timestamps = {
    .type        = BPF_MAP_TYPE_LRU_HASH,
    .key_size    = sizeof(struct flow_key),
    .value_size  = sizeof(__u64),
    .max_entries = 8192,
};

/*
 * Ring buffer: RTT events delivered to userspace.
 * max_entries = ring size in bytes; must be a power-of-2 multiple of page size.
 */
struct bpf_map_def SEC("maps") rtt_events = {
    .type        = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1 << 16,  /* 64 KB ≈ 1 000 events before wrap */
};

/*
 * Parse an Ethernet-framed IPv4 or IPv6 TCP packet.
 * Fills *key with the five-tuple and sets *tcph_out to the TCP header.
 * Returns 0 on success, -1 if the packet is not IPv4/IPv6 TCP or if any
 * bounds check fails.
 */
static __always_inline int parse_tcp(void *data, void *data_end,
                                      struct flow_key *key,
                                      struct tcphdr  **tcph_out)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __u16 proto = bpf_ntohs(eth->h_proto);

    if (proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return -1;
        if (iph->protocol != IPPROTO_TCP)
            return -1;

        __u32 ihl = iph->ihl * 4;
        if (ihl < 20)  /* minimum IP header length */
            return -1;
        struct tcphdr *tcph = (void *)iph + ihl;
        if ((void *)(tcph + 1) > data_end)
            return -1;

        __builtin_memset(key, 0, sizeof(*key));
        key->family    = AF_INET;
        key->src_ip[0] = iph->saddr;  /* network byte order */
        key->dst_ip[0] = iph->daddr;
        key->src_port  = bpf_ntohs(tcph->source);
        key->dst_port  = bpf_ntohs(tcph->dest);
        *tcph_out = tcph;
        return 0;

    } else if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return -1;
        if (ip6h->nexthdr != IPPROTO_TCP)  /* extension headers not supported */
            return -1;

        struct tcphdr *tcph = (void *)(ip6h + 1);
        if ((void *)(tcph + 1) > data_end)
            return -1;

        __builtin_memset(key, 0, sizeof(*key));
        key->family = AF_INET6;
        __builtin_memcpy(key->src_ip, &ip6h->saddr, 16);
        __builtin_memcpy(key->dst_ip, &ip6h->daddr, 16);
        key->src_port = bpf_ntohs(tcph->source);
        key->dst_port = bpf_ntohs(tcph->dest);
        *tcph_out = tcph;
        return 0;
    }

    return -1;
}

SEC("tc")
int measure_rtt_tc(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct flow_key key  = {};
    struct tcphdr  *tcph = NULL;

    if (parse_tcp(data, data_end, &key, &tcph) < 0)
        return TC_ACT_OK;

    /* Pure SYN: LAN client opening a new connection (ingress path) */
    if (tcph->syn && !tcph->ack && !tcph->rst && !tcph->fin) {
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&syn_timestamps, &key, &ts, BPF_ANY);

    /* SYN-ACK: WAN server reply heading back to LAN client (egress path) */
    } else if (tcph->syn && tcph->ack && !tcph->rst && !tcph->fin) {
        /*
         * Reverse the five-tuple to find the original SYN entry:
         *   SYN was recorded as  src=client  dst=server
         *   SYN-ACK arrives as   src=server  dst=client
         */
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

            struct rtt_event *e = bpf_ringbuf_reserve(&rtt_events, sizeof(*e), 0);
            if (e) {
                e->family      = key.family;
                e->pad[0] = e->pad[1] = e->pad[2] = 0;
                /* LAN client = SYN src = SYN-ACK dst */
                __builtin_memcpy(e->client_ip, key.dst_ip, sizeof(e->client_ip));
                e->client_port = key.dst_port;
                /* WAN server = SYN-ACK src */
                __builtin_memcpy(e->server_ip, key.src_ip, sizeof(e->server_ip));
                e->server_port = key.src_port;
                e->rtt_us      = (__u32)(rtt_ns / 1000);
                bpf_ringbuf_submit(e, 0);
            }
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

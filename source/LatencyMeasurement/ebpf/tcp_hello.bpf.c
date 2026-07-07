/*
 * tcp_hello.bpf.c - eBPF socket_filter: LAN-client RTT via TCP handshake timing
 *
 * Attached to an AF_PACKET raw socket on the LAN interface (e.g. brlan0
 * or the physical port eth1) by tcp_loader using SO_ATTACH_BPF.
 * AF_PACKET is the same hook point as libpcap and is visible even on
 * platforms where hardware offload (e.g. BCM3390 Runner) bypasses TC.
 *
 * How it works
 * ─────────────
 *   Every packet on the interface runs through this program.
 *
 *   TCP SYN  (from LAN client → WAN):
 *     Store flow_key → ktime_ns in syn_timestamps LRU hash map.
 *     Return 0 (discard from socket receive buffer, no userspace wakeup).
 *
 *   TCP SYN-ACK (from WAN → LAN client):
 *     Reverse the flow key, look up the stored SYN timestamp.
 *     Compute RTT = now − SYN_ts, write rtt_event to rtt_events ARRAY map.
 *     Return ETH_HLEN to queue one frame to the AF_PACKET socket, which
 *     wakes the blocking recv() in the loader — zero-latency notification.
 *
 *   All other packets: return 0 (no wakeup, no map write).
 *
 * The SYN→SYN-ACK delta is the WAN RTT as seen by the LAN client.
 * Stale SYN entries are evicted by the LRU map once it reaches max_entries.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * Self-contained network header definitions.
 *
 * linux/ip.h, linux/ipv6.h, linux/tcp.h, linux/if_ether.h and
 * linux/pkt_cls.h are intentionally NOT included.  Those kernel UAPI
 * headers pull in asm/byteorder.h from the cross-compilation sysroot,
 * which chains back to linux/swab.h and requires __attribute_const__
 * from linux/compiler.h — a file that is outside the UAPI tree and
 * never reachable in this include path.  Defining the handful of
 * structs and constants we actually need avoids the conflict entirely.
 */

#define AF_INET  2
#define AF_INET6 10

/* Socket_filter return codes --------------------------------------------- */
/* Returning 0 discards the packet from the socket receive buffer.          */
/* Returning ETH_HLEN queues the packet, waking the blocking recv().        */

/* Ethernet ---------------------------------------------------------------- */
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_ALEN   6
#define ETH_HLEN   14   /* 6 (dst) + 6 (src) + 2 (type) */

struct ethhdr {
    __u8  h_dest[ETH_ALEN];
    __u8  h_source[ETH_ALEN];
    __u16 h_proto;              /* network byte order */
} __attribute__((packed));

/* IPv4 -------------------------------------------------------------------- */
#define IPPROTO_TCP 6

struct iphdr {
    __u8  ihl_version;          /* high nibble = version, low nibble = IHL */
    __u8  tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;                /* network byte order */
    __u32 daddr;
} __attribute__((packed));

/* IPv6 -------------------------------------------------------------------- */
struct ipv6hdr {
    __u8  version_prio;         /* high nibble = version */
    __u8  flow_lbl[3];
    __u16 payload_len;
    __u8  nexthdr;
    __u8  hop_limit;
    __u8  saddr[16];            /* network byte order */
    __u8  daddr[16];
} __attribute__((packed));

/* TCP --------------------------------------------------------------------- */
struct tcphdr {
    __u16 source;               /* network byte order */
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u8  doff_res;             /* high nibble = data offset */
    __u8  flags;                /* bit0=FIN bit1=SYN bit2=RST bit3=PSH bit4=ACK */
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
} __attribute__((packed));

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_ACK 0x10

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
 * RTT event written to rtt_events ARRAY map; userspace reads via poll.
 * client_* = LAN-side host;  server_* = WAN-side peer.
 */
struct rtt_event {
    __u32 client_ip[4];
    __u32 server_ip[4];
    __u16 client_port;  /* host byte order */
    __u16 server_port;
    __u8  family;       /* AF_INET or AF_INET6 */
    __u8  pad[3];
    __u32 rtt_us;       /* raw nanoseconds (lower 32 bits of SYN→SYN-ACK delta) */
};

/*
 * pkt_count[0] = total Ethernet frames seen
 * pkt_count[1] = frames successfully parsed as IPv4/IPv6 TCP
 * pkt_count[2] = TCP SYN frames detected
 * pkt_count[3] = TCP SYN-ACK frames detected
 * pkt_count[4] = TCP SYN-ACK: matching SYN found (RTT computed + written)
 * pkt_count[5] = TCP SYN-ACK: no matching SYN (key mismatch or SYN missed)
 * pkt_count[6] = RTT events successfully written to rtt_events map
 * pkt_count[7] = (reserved)
 */
struct bpf_map_def SEC("maps") pkt_count = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u64),
    .max_entries = 8,
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
 * Output map: BPF writes the latest RTT event here; userspace polls it.
 * Plain ARRAY + bpf_map_update_elem avoids bpf_perf_event_output which
 * returns ENOTSUPP (-524) for SOCKET_FILTER in softirq context on this
 * vendor BCM3390 kernel.
 * max_entries=32 gives a small circular ring so back-to-back connections
 * are not lost; the write index is stored at slot 0 of rtt_write_idx.
 */
struct bpf_map_def SEC("maps") rtt_events = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct rtt_event),
    .max_entries = 32,
};

/* Write cursor for rtt_events ring (slot 0 = next write index). */
struct bpf_map_def SEC("maps") rtt_write_idx = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 1,
};

/*
 * Parse an Ethernet-framed IPv4 or IPv6 TCP packet using bpf_skb_load_bytes().
 *
 * bpf_skb_load_bytes() copies header bytes into stack-local structs.
 * This deliberately avoids skb->data / skb->data_end pointer arithmetic
 * ("direct packet access"), which sets fp->aux->pkt_access and causes the
 * ARM 32-bit BPF JIT to refuse the program with ENOTSUPP post-verifier.
 *
 * Fills *key with the five-tuple and *flags_out with the TCP flags byte.
 * Returns 0 on success, -1 otherwise.
 */
static __always_inline int parse_tcp(struct __sk_buff *skb,
                                      struct flow_key *key, __u8 *flags_out)
{
    __u16 proto;
    /* EtherType sits at byte offset 12 in the Ethernet header */
    if (bpf_skb_load_bytes(skb, 12, &proto, sizeof(proto)) < 0)
        return -1;
    proto = bpf_ntohs(proto);

    if (proto == ETH_P_IP) {
        struct iphdr iph;
        if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)) < 0)
            return -1;
        if (iph.protocol != IPPROTO_TCP)
            return -1;

        __u32 ihl = (iph.ihl_version & 0x0F) * 4;
        if (ihl < 20)
            return -1;

        struct tcphdr tcph;
        if (bpf_skb_load_bytes(skb, ETH_HLEN + ihl, &tcph, sizeof(tcph)) < 0)
            return -1;

        __builtin_memset(key, 0, sizeof(*key));
        key->family    = AF_INET;
        key->src_ip[0] = iph.saddr;   /* network byte order */
        key->dst_ip[0] = iph.daddr;
        key->src_port  = bpf_ntohs(tcph.source);
        key->dst_port  = bpf_ntohs(tcph.dest);
        *flags_out = tcph.flags;
        return 0;

    } else if (proto == ETH_P_IPV6) {
        struct ipv6hdr ip6h;
        if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip6h, sizeof(ip6h)) < 0)
            return -1;
        if (ip6h.nexthdr != IPPROTO_TCP)   /* extension headers not followed */
            return -1;

        struct tcphdr tcph;
        __u32 tcp_off = ETH_HLEN + (__u32)sizeof(ip6h);
        if (bpf_skb_load_bytes(skb, tcp_off, &tcph, sizeof(tcph)) < 0)
            return -1;

        __builtin_memset(key, 0, sizeof(*key));
        key->family = AF_INET6;
        __builtin_memcpy(key->src_ip, ip6h.saddr, 16);
        __builtin_memcpy(key->dst_ip, ip6h.daddr, 16);
        key->src_port = bpf_ntohs(tcph.source);
        key->dst_port = bpf_ntohs(tcph.dest);
        *flags_out = tcph.flags;
        return 0;
    }

    return -1;
}

/*
 * SEC("socket_filter") attaches this program to an AF_PACKET raw socket
 * created by tcp_loader.  AF_PACKET is the same hook point used by libpcap
 * and is NOT bypassed by Broadcom ARCHER hardware offload, unlike TC hooks.
 *
    /* SEC comment updated: we return 0 for most packets, ETH_HLEN only when
     * an RTT event is written so the socket wakes userspace precisely. */     * bpf_perf_event_output returns ENOTSUPP (-524) for SOCKET_FILTER in
     * softirq context on the BCM3390 vendor kernel; bpf_map_update_elem
     * works correctly from softirq and is used instead. */
SEC("socket_filter")
int measure_rtt_tc(struct __sk_buff *skb)
{
    struct flow_key key = {};
    __u8 flags = 0;

    /* [0] total frames */
    __u32 idx = 0;
    __u64 *cnt = bpf_map_lookup_elem(&pkt_count, &idx);
    if (cnt)
        *cnt = *cnt + 1;

    if (parse_tcp(skb, &key, &flags) < 0)
        return 0;  /* not TCP — discard from socket receive buffer */

    /* [1] successfully parsed as TCP */
    idx = 1;
    cnt = bpf_map_lookup_elem(&pkt_count, &idx);
    if (cnt)
        *cnt = *cnt + 1;

    /*
     * Mask the four control bits we care about; ECE/CWR (bits 6-7) are
     * ignored so ECN-capable SYN-ACKs are still matched correctly.
     */
    __u8 ctl = flags & (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN);

    /* Pure SYN: LAN client opening a new connection (ingress path) */
    if (ctl == TCP_FLAG_SYN) {
        /* [2] SYN counter */
        idx = 2;
        cnt = bpf_map_lookup_elem(&pkt_count, &idx);
        if (cnt) *cnt = *cnt + 1;

        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&syn_timestamps, &key, &ts, BPF_ANY);

    } else if (ctl == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
        /* [3] SYN-ACK counter */
        idx = 3;
        cnt = bpf_map_lookup_elem(&pkt_count, &idx);
        if (cnt) *cnt = *cnt + 1;
        struct flow_key syn_key = {};
        syn_key.family   = key.family;
        __builtin_memcpy(syn_key.src_ip, key.dst_ip, sizeof(syn_key.src_ip));
        __builtin_memcpy(syn_key.dst_ip, key.src_ip, sizeof(syn_key.dst_ip));
        syn_key.src_port = key.dst_port;
        syn_key.dst_port = key.src_port;

        __u64 *syn_ts = bpf_map_lookup_elem(&syn_timestamps, &syn_key);
        if (syn_ts) {
            /* [4] SYN-ACK match found — RTT will be computed */
            idx = 4; cnt = bpf_map_lookup_elem(&pkt_count, &idx);
            if (cnt) *cnt = *cnt + 1;
            __u64 rtt_ns = bpf_ktime_get_ns() - *syn_ts;
            bpf_map_delete_elem(&syn_timestamps, &syn_key);

            struct rtt_event ev = {};
            ev.family      = key.family;
            /* LAN client = SYN src = SYN-ACK dst */
            __builtin_memcpy(ev.client_ip, key.dst_ip, sizeof(ev.client_ip));
            ev.client_port = key.dst_port;
            /* WAN server = SYN-ACK src */
            __builtin_memcpy(ev.server_ip, key.src_ip, sizeof(ev.server_ip));
            ev.server_port = key.src_port;
            /* Store raw nanoseconds (lower 32 bits) — no division in BPF.
             * Safe for RTTs up to UINT32_MAX ns ≈ 4.29 s.
             * Exact ms conversion is done in userspace. */
            ev.rtt_us      = (__u32)rtt_ns;

            /* Write to the rtt_events array ring.
             * bpf_map_update_elem works in softirq context (confirmed);
             * bpf_perf_event_output returns ENOTSUPP here (softirq). */
            __u32 widx_key = 0;
            __u32 *wp = bpf_map_lookup_elem(&rtt_write_idx, &widx_key);
            if (wp) {
                __u32 slot = *wp % 32;
                bpf_map_update_elem(&rtt_events, &slot, &ev, BPF_ANY);
                *wp = *wp + 1;  /* advance write cursor (non-atomic: ok for PoC) */
            }

            /* [6/7] track success for diagnostic */
            idx = 6; cnt = bpf_map_lookup_elem(&pkt_count, &idx);
            if (cnt) *cnt = *cnt + 1;

            /* Return ETH_HLEN to queue one frame to the AF_PACKET socket.
             * This wakes the blocking recv() in the loader immediately
             * without any polling delay. All other packets return 0. */
            return ETH_HLEN;
        } else {
            /* [5] SYN-ACK lookup failed — key mismatch or SYN never seen */
            idx = 5; cnt = bpf_map_lookup_elem(&pkt_count, &idx);
            if (cnt) *cnt = *cnt + 1;
        }
    }

    return 0;  /* discard — no RTT event, no wakeup needed */
}

char _license[] SEC("license") = "GPL";

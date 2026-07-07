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

/* Ethernet ----------------------------------------------------------------
 * Pulled from the standard kernel UAPI header; safe to include because
 * linux/if_ether.h has no bitfield structs and no problematic include chain.
 */
#include <linux/if_ether.h>

/* IPv4 -------------------------------------------------------------------- */
#define IPPROTO_TCP 6

/*
 * Custom struct definitions for iphdr, ipv6hdr, and tcphdr are kept
 * intentionally instead of including linux/ip.h, linux/ipv6.h, linux/tcp.h.
 *
 * The standard kernel headers use bitfields for multi-bit fields (ihl:4,
 * version:4, syn:1, ack:1 …).  For clang -target bpf, the bitfield layout
 * depends on __BIG_ENDIAN_BITFIELD vs __LITTLE_ENDIAN_BITFIELD, which is
 * ambiguous for the BPF target and is a known source of subtle endianness
 * bugs in BPF programs.
 *
 * These custom structs use plain bytes/shorts — correct and unambiguous
 * regardless of the compilation target's byte order.
 */

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
    __u32 rtt_ns;       /* raw SYN→SYN-ACK delta in nanoseconds (lower 32 bits) */
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
 * Return values:
 *   0         — discard from socket receive buffer (no userspace wakeup).
 *   ETH_HLEN  — queue frame to socket, waking the blocking recv() in the
 *               loader.  Used only when an RTT event is written to the map.
 *
 * Note: bpf_perf_event_output returns ENOTSUPP (-524) for SOCKET_FILTER in
 * softirq context on the BCM3390 vendor kernel; bpf_map_update_elem works
 * correctly from softirq and is used instead.
 */
SEC("socket_filter")
int measure_rtt_tc(struct __sk_buff *skb)
{
    struct flow_key key = {};
    __u8 flags = 0;

    if (parse_tcp(skb, &key, &flags) < 0)
        return 0;  /* not TCP -- discard from socket receive buffer */

    /*
     * Mask the four control bits we care about; ECE/CWR (bits 6-7) are
     * ignored so ECN-capable SYN-ACKs are still matched correctly.
     */
    __u8 ctl = flags & (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN);

    /* Pure SYN: LAN client opening a new connection */
    if (ctl == TCP_FLAG_SYN) {
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&syn_timestamps, &key, &ts, BPF_ANY);

    } else if (ctl == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
        /* SYN-ACK: look up the matching SYN and compute RTT */
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
            ev.family      = key.family;
            /* LAN client = SYN src = SYN-ACK dst */
            __builtin_memcpy(ev.client_ip, key.dst_ip, sizeof(ev.client_ip));
            ev.client_port = key.dst_port;
            /* WAN server = SYN-ACK src */
            __builtin_memcpy(ev.server_ip, key.src_ip, sizeof(ev.server_ip));
            ev.server_port = key.src_port;
            /* Store raw nanoseconds (lower 32 bits).
             * Safe for RTTs up to UINT32_MAX ns (~4.29 s).
             * Exact ms conversion is done in userspace. */
            ev.rtt_ns      = (__u32)rtt_ns;

            /* Write to the rtt_events ARRAY ring, then return ETH_HLEN to
             * queue one frame to the AF_PACKET socket.  This wakes the
             * blocking recv() in the loader -- zero polling delay. */
            __u32 widx_key = 0;
            __u32 *wp = bpf_map_lookup_elem(&rtt_write_idx, &widx_key);
            if (wp) {
                __u32 slot = *wp % 32;
                bpf_map_update_elem(&rtt_events, &slot, &ev, BPF_ANY);
                *wp = *wp + 1;  /* advance write cursor (non-atomic: ok for PoC) */
            }
            return ETH_HLEN;
        }
    }

    return 0;  /* discard -- no RTT event, no wakeup needed */
}

char _license[] SEC("license") = "GPL";

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

/* TC return code ---------------------------------------------------------- */
#define TC_ACT_OK 0

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
 * SEC("classifier") keeps expected_attach_type = 0 (old-style TC/cls_bpf).
 * SEC("tc") in libbpf >= 1.3 sets expected_attach_type = BPF_TCX_INGRESS (28),
 * which kernels older than 6.6 reject with ENOTSUPP post-verifier.
 * The bpf_tc_hook_create/bpf_tc_attach loader API requires the old-style type.
 */
SEC("classifier")
int measure_rtt_tc(struct __sk_buff *skb)
{
    struct flow_key key = {};
    __u8 flags = 0;

    if (parse_tcp(skb, &key, &flags) < 0)
        return TC_ACT_OK;

    /*
     * Mask the four control bits we care about; ECE/CWR (bits 6-7) are
     * ignored so ECN-capable SYN-ACKs are still matched correctly.
     */
    __u8 ctl = flags & (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN);

    /* Pure SYN: LAN client opening a new connection (ingress path) */
    if (ctl == TCP_FLAG_SYN) {
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&syn_timestamps, &key, &ts, BPF_ANY);

    /* SYN-ACK: WAN server reply heading back to LAN client (egress path) */
    } else if (ctl == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
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
                /* Cast to __u32 before dividing: ARM 32-bit BPF JIT does not
                 * support BPF_ALU64|BPF_DIV (64-bit division).  Safe for all
                 * realistic RTTs — UINT32_MAX ns ≈ 4.29 s. */
                e->rtt_us      = (__u32)rtt_ns / 1000;
                bpf_ringbuf_submit(e, 0);
            }
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

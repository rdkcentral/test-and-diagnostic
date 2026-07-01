/*
 * tcp_hello.bpf.c - eBPF sock_ops program: per-connection RTT measurement
 *
 * For each TCP connection (IPv4 and IPv6):
 *   - On ESTABLISHED: opt-in to RTT callbacks
 *   - On RTT_CB: push an rtt_event to the ring buffer
 *
 * The ring buffer is mmap()'d by userspace (via libbpf ring_buffer API),
 * so each RTT sample is delivered without extra copies.
 *
 * Event: 5-tuple (family, local_ip, remote_ip, local_port, remote_port) + srtt_us
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET  2
#define AF_INET6 10

/*
 * RTT event record — one pushed to the ring buffer per RTT_CB fire.
 * local_ip6 / remote_ip6: 128-bit in network byte order.
 *   AF_INET:  [0] = IPv4 addr, [1-3] = 0
 *   AF_INET6: full 128-bit across all four words
 */
struct rtt_event {
    __u32 local_ip6[4];
    __u32 remote_ip6[4];
    __u16 local_port;       /* host byte order */
    __u16 remote_port;      /* host byte order */
    __u8  family;           /* AF_INET or AF_INET6 */
    __u8  pad[3];
    __u32 srtt_us;          /* smoothed RTT in microseconds */
};

/*
 * Ring buffer map — userspace mmap()s this region to read events.
 * max_entries = ring size in bytes; must be power-of-2 multiple of page size.
 * Legacy map definition (no BTF) required without CONFIG_DEBUG_INFO_BTF.
 */
struct bpf_map_def SEC("maps") rtt_events = {
    .type        = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1 << 16,  /* 64 KB — holds ~1000 events before wrap */
};

SEC("sockops")
int measure_rtt(struct bpf_sock_ops *skops)
{
    __u8 family = (__u8)skops->family;
    if (family != AF_INET && family != AF_INET6)
        return 1;

    switch (skops->op) {

    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:    /* client-side handshake done */
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:   /* server-side handshake done */
        /* Opt this socket in to RTT update callbacks */
        bpf_sock_ops_cb_flags_set(skops,
            skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_RTT_CB_FLAG);
        break;

    case BPF_SOCK_OPS_RTT_CB:
        {
            /*
             * Reserve space in the ring buffer.
             * If the ring is full the event is silently dropped (non-blocking).
             */
            struct rtt_event *e = bpf_ringbuf_reserve(&rtt_events, sizeof(*e), 0);
            if (!e)
                break;

            e->family      = family;
            e->pad[0]      = 0;
            e->pad[1]      = 0;
            e->pad[2]      = 0;
            e->local_port  = (__u16)skops->local_port;
            e->remote_port = (__u16)bpf_ntohl(skops->remote_port);
            /* srtt_us is stored as srtt << 3 internally; shift right to get us */
            e->srtt_us     = skops->srtt_us >> 3;

            if (family == AF_INET) {
                e->local_ip6[0]  = skops->local_ip4;
                e->local_ip6[1]  = 0;
                e->local_ip6[2]  = 0;
                e->local_ip6[3]  = 0;
                e->remote_ip6[0] = skops->remote_ip4;
                e->remote_ip6[1] = 0;
                e->remote_ip6[2] = 0;
                e->remote_ip6[3] = 0;
            } else {
                e->local_ip6[0]  = skops->local_ip6[0];
                e->local_ip6[1]  = skops->local_ip6[1];
                e->local_ip6[2]  = skops->local_ip6[2];
                e->local_ip6[3]  = skops->local_ip6[3];
                e->remote_ip6[0] = skops->remote_ip6[0];
                e->remote_ip6[1] = skops->remote_ip6[1];
                e->remote_ip6[2] = skops->remote_ip6[2];
                e->remote_ip6[3] = skops->remote_ip6[3];
            }

            bpf_ringbuf_submit(e, 0);
        }
        break;

    default:
        break;
    }
    return 1;
}

char _license[] SEC("license") = "GPL";

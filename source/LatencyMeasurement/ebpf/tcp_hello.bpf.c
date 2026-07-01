/*
 * tcp_hello.bpf.c - eBPF sock_ops program: per-connection RTT measurement
 *
 * For each TCP connection (IPv4 and IPv6):
 *   - On ESTABLISHED: opt-in to RTT callbacks
 *   - On RTT_CB: read kernel's smoothed RTT, store min/max/latest in a hash map
 *
 * Map key:   5-tuple (family, local_ip, remote_ip, local_port, remote_port)
 * Map value: srtt_us (latest), min_rtt_us, max_rtt_us, sample count
 *
 * Userspace reads the hash map and displays per-connection RTT stats.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET  2
#define AF_INET6 10

/*
 * Connection 5-tuple — map key.
 * local_ip6 / remote_ip6: 128-bit address in network byte order.
 *   For AF_INET:  [0] = IPv4 address, [1-3] = 0
 *   For AF_INET6: full 128-bit address across all four words
 * local_port:  host byte order (as given by skops)
 * remote_port: host byte order (converted from skops with bpf_ntohl)
 * family:      AF_INET (2) or AF_INET6 (10)
 * pad[3]:      explicit zero padding — must stay zeroed for map lookups
 */
struct conn_key {
    __u32 local_ip6[4];
    __u32 remote_ip6[4];
    __u16 local_port;
    __u16 remote_port;
    __u8  family;
    __u8  pad[3];
};

/*
 * RTT statistics per connection — map value.
 * All RTT values in microseconds.
 */
struct rtt_val {
    __u32 srtt_us;      /* latest kernel smoothed RTT  */
    __u32 min_rtt_us;   /* minimum RTT seen            */
    __u32 max_rtt_us;   /* maximum RTT seen            */
    __u32 samples;      /* number of RTT_CB fires      */
};

/*
 * Hash map: conn_key → rtt_val
 * Holds up to 256 concurrent TCP connections.
 * Legacy map definition (no BTF) — required without CONFIG_DEBUG_INFO_BTF.
 */
struct bpf_map_def SEC("maps") rtt_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct conn_key),
    .value_size  = sizeof(struct rtt_val),
    .max_entries = 256,
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
             * skops->srtt_us is stored as srtt << 3 internally.
             * Shift right by 3 to get the actual smoothed RTT in microseconds.
             */
            __u32 rtt_us = skops->srtt_us >> 3;

            struct conn_key key = {};
            key.family      = family;
            key.local_port  = (__u16)skops->local_port;
            key.remote_port = (__u16)bpf_ntohl(skops->remote_port);
            if (family == AF_INET) {
                key.local_ip6[0]  = skops->local_ip4;
                key.remote_ip6[0] = skops->remote_ip4;
            } else {
                key.local_ip6[0]  = skops->local_ip6[0];
                key.local_ip6[1]  = skops->local_ip6[1];
                key.local_ip6[2]  = skops->local_ip6[2];
                key.local_ip6[3]  = skops->local_ip6[3];
                key.remote_ip6[0] = skops->remote_ip6[0];
                key.remote_ip6[1] = skops->remote_ip6[1];
                key.remote_ip6[2] = skops->remote_ip6[2];
                key.remote_ip6[3] = skops->remote_ip6[3];
            }

            struct rtt_val *existing = bpf_map_lookup_elem(&rtt_map, &key);
            if (existing) {
                /* Update in place — direct write safe for HASH map values */
                existing->srtt_us = rtt_us;
                existing->samples++;
                if (rtt_us < existing->min_rtt_us) existing->min_rtt_us = rtt_us;
                if (rtt_us > existing->max_rtt_us) existing->max_rtt_us = rtt_us;
            } else {
                /* First RTT sample for this connection */
                struct rtt_val val = {};
                val.srtt_us    = rtt_us;
                val.min_rtt_us = rtt_us;
                val.max_rtt_us = rtt_us;
                val.samples    = 1;
                bpf_map_update_elem(&rtt_map, &key, &val, BPF_ANY);
            }
        }
        break;

    default:
        break;
    }
    return 1;
}

char _license[] SEC("license") = "GPL";

/*
 * tcp_hello.bpf.c - eBPF sock_ops program: per-connection RTT measurement
 *
 * For each TCP connection (IPv4):
 *   - On ESTABLISHED: opt-in to RTT callbacks
 *   - On RTT_CB: read kernel's smoothed RTT, store min/max/latest in a hash map
 *
 * Map key:   4-tuple (local_ip, remote_ip, local_port, remote_port)
 * Map value: srtt_us (latest), min_rtt_us, max_rtt_us, sample count
 *
 * Userspace reads the hash map and displays per-connection RTT stats.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2

/*
 * Connection 4-tuple — map key.
 * local_ip4 / remote_ip4: network byte order (as given by skops)
 * local_port:  host byte order (as given by skops)
 * remote_port: host byte order (converted from skops with bpf_ntohl)
 */
struct conn_key {
    __u32 local_ip4;
    __u32 remote_ip4;
    __u16 local_port;
    __u16 remote_port;
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
    /* Only handle IPv4 — IPv6 support can be added later */
    if (skops->family != AF_INET)
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
            key.local_ip4   = skops->local_ip4;
            key.remote_ip4  = skops->remote_ip4;
            key.local_port  = (__u16)skops->local_port;
            key.remote_port = (__u16)bpf_ntohl(skops->remote_port);

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

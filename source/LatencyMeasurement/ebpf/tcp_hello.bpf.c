/*
 * tcp_hello.bpf.c - Minimal eBPF sock_ops program for TCP RTT measurement POC
 *
 * Purpose: Counts how many times the kernel fires BPF_SOCK_OPS_RTT_CB.
 *          Baby step to verify:
 *            1. BPF program loads into the kernel
 *            2. sock_ops hook fires on real TCP traffic
 *            3. BPF map is readable from userspace
 *
 * Compile:
 *   clang -O2 -target bpf \
 *     -I <kernel_src>/include/uapi \
 *     -I <kernel_src>/include \
 *     -I <libbpf>/include \
 *     -c tcp_hello.bpf.c -o tcp_hello.bpf.o
 *
 * Load (via tcp_loader):
 *   ./tcp_loader
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * Single-entry ARRAY map — key 0 holds the RTT callback counter.
 * Userspace reads this to confirm the BPF program is running.
 *
 * Using legacy map definition (SEC("maps") not SEC(".maps")) to avoid
 * BTF dependency. The new BTF-based syntax (SEC(".maps") with __uint/__type)
 * requires CONFIG_DEBUG_INFO_BTF=y in the kernel, which is not set.
 */
struct bpf_map_def SEC("maps") rtt_counter = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u64),
    .max_entries = 1,
};

/*
 * count_rtt - called by the kernel TCP stack on sock_ops events.
 *
 * IMPORTANT: BPF_SOCK_OPS_RTT_CB does NOT fire automatically.
 * You must opt-in per-connection by setting BPF_SOCK_OPS_RTT_CB_FLAG
 * when the connection is established. Without this, RTT callbacks
 * never fire even though the program is attached.
 *
 * Flow:
 *   1. Connection established → ACTIVE/PASSIVE_ESTABLISHED_CB fires
 *   2. We call bpf_sock_ops_cb_flags_set() to enable RTT_CB for this socket
 *   3. On each RTT update → RTT_CB fires → we increment the counter
 *
 * skops->srtt_us >> 3 = smoothed RTT in microseconds
 */
SEC("sockops")
int count_rtt(struct bpf_sock_ops *skops)
{
    switch (skops->op) {

    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:   /* TCP handshake done (client side) */
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:  /* TCP handshake done (server side) */
        /* Opt this socket in to RTT callbacks */
        bpf_sock_ops_cb_flags_set(skops,
            skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_RTT_CB_FLAG);
        break;

    case BPF_SOCK_OPS_RTT_CB:  /* RTT updated for an opted-in socket */
        {
            __u32 key = 0;
            __u64 *val = bpf_map_lookup_elem(&rtt_counter, &key);
            if (val)
                (*val)++;  /* direct write — ARM32 JIT has no BPF_ATOMIC support */
        }
        break;
    }
    return 1;
}

char _license[] SEC("license") = "GPL";

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
 * count_rtt - called by the kernel TCP stack on every RTT update.
 *
 * skops->op values of interest:
 *   BPF_SOCK_OPS_RTT_CB      : kernel updated srtt for this connection
 *   BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB  : TCP handshake complete (client)
 *   BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB : TCP handshake complete (server)
 *
 * skops->srtt_us >> 3 = smoothed RTT in microseconds (kernel internal format)
 */
SEC("sockops")
int count_rtt(struct bpf_sock_ops *skops)
{
    if (skops->op == BPF_SOCK_OPS_RTT_CB) {
        __u32 key = 0;
        __u64 *val = bpf_map_lookup_elem(&rtt_counter, &key);
        if (val)
            (*val)++;  /* direct write — ARM32 JIT has no BPF_ATOMIC support */
    }
    return 1;
}

char _license[] SEC("license") = "GPL";

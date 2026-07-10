/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * tcp_rtt.h - Types shared between tcp_hello.bpf.c and tcp_loader.c
 *
 * Included by the BPF program (compiled with clang -target bpf) and by the
 * userspace loader (compiled with the Yocto cross-compiler).  Keep this file
 * free of any headers that differ between the two compilation environments.
 */

#ifndef TCP_RTT_H
#define TCP_RTT_H

/*
 * RTT event: written to the rtt_events ARRAY map by the BPF program;
 * read from the same map by tcp_loader's poll thread.
 *
 * client_*    = LAN-side host (source of the TCP SYN)
 * server_*    = WAN-side peer (destination of the TCP SYN)
 * wan_rtt_ns  = SYN → SYN-ACK delta in nanoseconds (gateway ↔ WAN server RTT)
 * lan_rtt_ns  = SYN-ACK → ACK delta in nanoseconds (client response time)
 *               Both are stored as lower 32 bits; safe up to ~4.29 s.
 */
struct rtt_event {
    __u32 client_ip[4];  /* AF_INET:  [0]=addr, [1-3]=0
                          * AF_INET6: full 128-bit in network byte order */
    __u32 server_ip[4];
    __u16 client_port;   /* host byte order */
    __u16 server_port;
    __u8  family;        /* AF_INET (2) or AF_INET6 (10) */
    __u8  pad[3];        /* explicit padding for struct alignment */
    __u32 wan_rtt_ns;    /* SYN → SYN-ACK  (network RTT to server) */
    __u32 lan_rtt_ns;    /* SYN-ACK → ACK  (LAN client response time) */
};

#endif /* TCP_RTT_H */

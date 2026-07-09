/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bpf_net_defs.h - Network protocol headers for BPF packet parsing.
 *
 * Uses the standard kernel UAPI headers (linux/ip.h, linux/ipv6.h,
 * linux/tcp.h) instead of hand-rolled structs.
 *
 * Endian handling
 * ---------------
 * clang -target bpf compiles for a big-endian BPF VM.  Network packets are
 * also big-endian (network byte order).  The kernel headers select struct
 * bitfield layout via __BIG_ENDIAN_BITFIELD / __LITTLE_ENDIAN_BITFIELD.
 *
 * Without intervention, the ARM arch headers (asm/byteorder.h) would define
 * __LITTLE_ENDIAN_BITFIELD.  For packet parsing on a big-endian BPF VM this
 * is wrong — 16-bit bitfields (e.g. tcphdr.doff/syn/ack) would map to the
 * wrong bits.  We force __BIG_ENDIAN_BITFIELD before the includes so that
 * bitfield members align with packet bytes.
 *
 * Struct access summary (changed from the plain-byte custom structs):
 *   iphdr   : iph.ihl / iph.version (bitfields) — no more ihl_version byte
 *   ipv6hdr : ip6h.saddr / ip6h.daddr are struct in6_addr, use &ip6h.saddr
 *   tcphdr  : tcph.syn / tcph.ack / tcph.fin / tcph.rst (bitfields)
 */

#ifndef __BPF_NET_DEFS_H
#define __BPF_NET_DEFS_H

/* ── Force big-endian bitfield layout ───────────────────────────────────── */
#ifdef __LITTLE_ENDIAN_BITFIELD
# undef __LITTLE_ENDIAN_BITFIELD
#endif
#ifndef __BIG_ENDIAN_BITFIELD
# define __BIG_ENDIAN_BITFIELD
#endif

/*
 * The kernel header chain pulls in linux/kasan-checks.h and
 * linux/kcsan-checks.h via asm-generic/rwonce.h.  These are kernel memory
 * sanitisers — they have no-op stubs when CONFIG_KASAN / CONFIG_KCSAN are
 * undefined, but those stubs still need bool and size_t.
 *
 * Provide the necessary types using clang built-ins, then define the
 * sanitiser include-guards and supply our own minimal stubs so that neither
 * header's full include chain is activated.
 */
#ifndef _SIZE_T
# define _SIZE_T
typedef __SIZE_TYPE__ size_t;
#endif

#ifndef _BOOL_DEFINED
# define _BOOL_DEFINED
typedef _Bool bool;
# define true  ((bool)1)
# define false ((bool)0)
#endif

/* Short-circuit the sanitiser headers — set their include guards before the
 * kernel headers open them, then supply the minimal stubs they export. */
#ifndef _LINUX_KASAN_CHECKS_H
# define _LINUX_KASAN_CHECKS_H
static inline bool __kasan_check_read(const volatile void *p, unsigned int size)  { return true; }
static inline bool __kasan_check_write(const volatile void *p, unsigned int size) { return true; }
static inline bool kasan_check_read(const volatile void *p, unsigned int size)    { return true; }
static inline bool kasan_check_write(const volatile void *p, unsigned int size)   { return true; }
#endif

#ifndef _LINUX_KCSAN_CHECKS_H
# define _LINUX_KCSAN_CHECKS_H
static inline void __kcsan_check_access(const volatile void *p, size_t size, int type) {}
static inline void kcsan_check_access(const volatile void *p, size_t size, int type)   {}
#endif

#include <linux/ip.h>      /* struct iphdr  (ihl, version, protocol, saddr, daddr) */
#include <linux/ipv6.h>    /* struct ipv6hdr (nexthdr, saddr, daddr) */
#include <linux/tcp.h>     /* struct tcphdr (source, dest, doff, syn, ack, fin, rst) */

/* ── Address family / protocol constants ─────────────────────────────────── */
/*
 * Kept as local defines rather than pulling in linux/socket.h / linux/in.h
 * to avoid heavy include chains in the minimal BPF build environment.
 */
#define AF_INET       2
#define AF_INET6     10
#define IPPROTO_TCP   6

/* ── Five-tuple flow key ─────────────────────────────────────────────────── */
/*
 * Used as key in the syn_timestamps LRU hash map.
 * SYN stored with (src=client, dst=server); SYN-ACK lookup reverses tuple.
 */
struct flow_key {
    __u32 src_ip[4]; /* AF_INET: [0]=addr, [1-3]=0 | AF_INET6: full 128-bit */
    __u32 dst_ip[4]; /* network byte order */
    __u16 src_port;  /* host byte order */
    __u16 dst_port;
    __u8  family;    /* AF_INET or AF_INET6 */
    __u8  pad[3];
};

#endif /* __BPF_NET_DEFS_H */

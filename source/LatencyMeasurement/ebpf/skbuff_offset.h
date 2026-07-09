/* SPDX-License-Identifier: GPL-2.0 */
/*
 * skbuff_offset.h - Compile-time computation of sk_buff->data byte offset.
 *
 * Replaces a hardcoded magic number with a transparent #ifdef chain that
 * accounts for every config-dependent field in struct sk_buff that precedes
 * the 'data' pointer.
 *
 * Requirements
 * ------------
 *   Compile with:
 *     -include $(KERNEL_SRC)/include/generated/autoconf.h
 *   so that CONFIG_xxx macros are defined before this header is processed.
 *
 * Validated on
 * ------------
 *   Linux 5.15 ARM32 (BCM3390/RDKB, cortexa15hf-neon)
 *   Confirmed offset = 188 via runtime scan (see git history for scan tool).
 *
 * How to re-verify after a kernel config change
 * -----------------------------------------------
 *   Re-enable the offset scan in tcp_hello.bpf.c (DBG_SCAN_OFF macro),
 *   rebuild, run tcp_loader and check [scan] output.  Update any fixed-size
 *   constants below if a new _SKB_OFF_FIXED block shifts.
 */

#ifndef __SKBUFF_OFFSET_H
#define __SKBUFF_OFFSET_H

/*
 * ── Fixed layout (ARM32, always present) ────────────────────────────────────
 *
 *  [  0] union { next(4), prev(4), dev(4) }     12
 *  [ 12] union { sk(4) }                         4
 *  [ 16] union { tstamp / skb_mstamp_ns }        8  (u64)
 *  [ 24] cb[48]                                 48
 *  [ 72] union { _skb_refdst(4), destructor(4) } 8
 *                                              ────
 *                                               80  ← _SKB_BASE
 */
#define _SKB_BASE  80

/*
 * ── CONFIG-dependent fields ──────────────────────────────────────────────────
 */

/* unsigned long _nfct  (4 bytes) */
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#  define _SKB_OFF_NFCT   4
#else
#  define _SKB_OFF_NFCT   0
#endif

/* struct net_device *dev_in  (4 bytes) — BCM NF offload ingress device */
#if defined(CONFIG_BCM_KF_CM) && defined(CONFIG_NF_CONNTRACK_OFFLOAD)
#  define _SKB_OFF_DEVIN  4
#else
#  define _SKB_OFF_DEVIN  0
#endif

/*
 * ── Fixed block 1: len … queue_mapping ──────────────────────────────────────
 *
 *  len(4) + data_len(4) + mac_len(2) + hdr_len(2) + queue_mapping(2) = 14
 *  + 2 bytes padding/cloned/active_ext to reach 4-byte alignment       = 4
 *                                                                      ────
 *                                                                        18
 *
 * Note: cloned(__u8) + active_extensions(__u8, if SKB_EXTENSIONS) fill the
 * two padding bytes before headers_start[0] forces 4-byte alignment.
 * Either way the block is always 18 bytes.
 */
#define _SKB_OFF_FIXED1  18

/*
 * ── Fixed block 2: bitfields (pkt_type … slow_gro) ──────────────────────────
 *
 * Several __u8 bitfield bytes (pkt_type, l4_hash, vlan_present, misc flags).
 * BCM adds recycle_hw_data:1 and pkt_flooded:1 to the pkt_type byte.
 * Total is consistently 6 bytes on this kernel (5 bitfield bytes + 1 pad
 * before tc_index which needs 2-byte alignment).
 */
#define _SKB_OFF_BITFIELDS  6

/* __u16 tc_index  (2 bytes + 2-byte pad to reach 4-byte csum alignment) */
#ifdef CONFIG_NET_SCHED
#  define _SKB_OFF_TC  4
#else
#  define _SKB_OFF_TC  0
#endif

/*
 * ── Fixed block 3: csum … vlan_tci ──────────────────────────────────────────
 *
 *  csum(4) + priority(4) + skb_iif(4) + hash(4) +
 *  vlan_proto(2) + vlan_tci(2)                    = 20
 */
#define _SKB_OFF_FIXED2  20

/* unsigned int napi_id / sender_cpu  (4 bytes) */
#if defined(CONFIG_NET_RX_BUSY_POLL) || defined(CONFIG_XPS)
#  define _SKB_OFF_NAPI  4
#else
#  define _SKB_OFF_NAPI  0
#endif

/* __u32 secmark  (4 bytes) */
#ifdef CONFIG_NETWORK_SECMARK
#  define _SKB_OFF_SECMARK  4
#else
#  define _SKB_OFF_SECMARK  0
#endif

/*
 * ── Fixed block 4: mark … mac_header ────────────────────────────────────────
 *
 *  mark(4) +
 *  inner_protocol(2) + inner_transport_header(2) +
 *  inner_network_header(2) + inner_mac_header(2) +
 *  protocol(2) + transport_header(2) +
 *  network_header(2) + mac_header(2)              = 20
 */
#define _SKB_OFF_FIXED3  20

/* __u32 gw_meta  (4 bytes) — Comcast gateway metadata */
#ifdef CONFIG_COMCAST_NF_GWMETA_SUPPORT
#  define _SKB_OFF_GWMETA  4
#else
#  define _SKB_OFF_GWMETA  0
#endif

/*
 * BCM SKB recycle fields  (12 bytes):
 *   int (*recycle)(struct sk_buff *skb)  (4)
 *   __u32 recycle_arg                    (4)
 *   void *recycle_shinfo                 (4)
 * CONFIG_SKB_RECYCLE is #defined unconditionally by linux/skbuff.h
 * when CONFIG_BCM_KF_CM is set.
 */
#if defined(CONFIG_BCM_KF_CM)   /* SKB_RECYCLE is auto-defined with BCM_KF_CM */
#  define _SKB_OFF_RECYCLE  12
#else
#  define _SKB_OFF_RECYCLE  0
#endif

/*
 * ── Fixed block 5: headers_end padding + tail/end/head ──────────────────────
 *
 *  headers_end[0] forces 4-byte alignment (may add up to 3 pad bytes), then:
 *  tail(4) + end(4) + head(4)                     = 12
 *
 *  ANDROID_KABI_RESERVE(1) and ANDROID_KABI_RESERVE(2) expand to nothing
 *  when CONFIG_ANDROID_KABI_RESERVE is not set (which is the case on this
 *  non-GKI vendor kernel).
 *
 *  With the recycle fields ending at a 4-byte boundary, headers_end needs
 *  4 bytes of pad for 8-byte alignment of the tail pointer.
 *  Total: 4 (pad) + 12 (tail/end/head) = 16.
 */
#ifdef CONFIG_ANDROID_KABI_RESERVE
#  define _SKB_OFF_KABI  16  /* two u64 KABI reserves */
#else
#  define _SKB_OFF_KABI   0
#endif

#define _SKB_OFF_TAIL_HEAD  16  /* 4-byte align pad + tail + end + head */

/*
 * ── Final offset ─────────────────────────────────────────────────────────────
 *
 * SKBUFF_DATA_OFFSET = byte offset of sk_buff->data from the start of the
 * struct.  On the current device (BCM_KF_CM=y, NF_CONNTRACK_OFFLOAD=y,
 * NET_SCHED=y, NET_RX_BUSY_POLL=y, NETWORK_SECMARK=n, GWMETA=n, KABI=n):
 *
 *   80+0+4+4+18+6+4+20+4+0+20+0+12+0+16 = 188  ✓
 */
#define SKBUFF_DATA_OFFSET  (  _SKB_BASE            \
                             + _SKB_OFF_NFCT         \
                             + _SKB_OFF_DEVIN        \
                             + _SKB_OFF_FIXED1       \
                             + _SKB_OFF_BITFIELDS    \
                             + _SKB_OFF_TC           \
                             + _SKB_OFF_FIXED2       \
                             + _SKB_OFF_NAPI         \
                             + _SKB_OFF_SECMARK      \
                             + _SKB_OFF_FIXED3       \
                             + _SKB_OFF_GWMETA       \
                             + _SKB_OFF_RECYCLE      \
                             + _SKB_OFF_KABI         \
                             + _SKB_OFF_TAIL_HEAD    )

#endif /* __SKBUFF_OFFSET_H */

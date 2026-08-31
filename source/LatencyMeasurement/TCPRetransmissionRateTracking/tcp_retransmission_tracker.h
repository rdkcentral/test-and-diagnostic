#ifndef TCP_RETRANSMISSION_TRACKER_H
#define TCP_RETRANSMISSION_TRACKER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TCP_RETRANSMISSION_MAX_PAIRS 1024
#define TCP_RETRANSMISSION_IP_MAX 46

#define TCP_RETRANSMISSION_PROTOCOL 6

typedef enum {
    TCP_RETRANSMISSION_RECORDED = 0,
    TCP_RETRANSMISSION_IGNORED = 1,
    TCP_RETRANSMISSION_CAPACITY_FULL = 2,
    TCP_RETRANSMISSION_INVALID_ARGUMENT = 3
} tcp_retransmission_result_t;

typedef struct {
    char source_ip[TCP_RETRANSMISSION_IP_MAX];
    char destination_ip[TCP_RETRANSMISSION_IP_MAX];
    uint32_t highest_sequence;
    uint64_t total_packets;
    uint64_t retransmitted_packets;
    bool in_use;
} tcp_retransmission_pair_t;

typedef struct {
    tcp_retransmission_pair_t pairs[TCP_RETRANSMISSION_MAX_PAIRS];
    size_t active_pairs;
} tcp_retransmission_tracker_t;

typedef struct {
    uint64_t total_packets;
    uint64_t retransmitted_packets;
    double retransmission_rate_percent;
} tcp_retransmission_stats_t;

void tcp_retransmission_tracker_init(tcp_retransmission_tracker_t *tracker);

tcp_retransmission_result_t tcp_retransmission_tracker_record(
    tcp_retransmission_tracker_t *tracker,
    uint8_t protocol,
    const char *source_ip,
    const char *destination_ip,
    uint32_t sequence,
    bool *is_retransmission);

int tcp_retransmission_tracker_get_pair_stats(
    const tcp_retransmission_tracker_t *tracker,
    const char *source_ip,
    const char *destination_ip,
    tcp_retransmission_stats_t *stats);

size_t tcp_retransmission_tracker_active_pairs(
    const tcp_retransmission_tracker_t *tracker);

#endif

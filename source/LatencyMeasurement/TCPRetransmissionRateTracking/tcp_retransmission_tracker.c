#include "tcp_retransmission_tracker.h"

#include <string.h>

static tcp_retransmission_pair_t *find_pair(
    tcp_retransmission_tracker_t *tracker,
    const char *source_ip,
    const char *destination_ip)
{
    size_t index;

    for (index = 0; index < TCP_RETRANSMISSION_MAX_PAIRS; index++) {
        tcp_retransmission_pair_t *pair = &tracker->pairs[index];

        if (pair->in_use && strcmp(pair->source_ip, source_ip) == 0 &&
            strcmp(pair->destination_ip, destination_ip) == 0) {
            return pair;
        }
    }

    return NULL;
}

void tcp_retransmission_tracker_init(tcp_retransmission_tracker_t *tracker)
{
    if (tracker != NULL) {
        memset(tracker, 0, sizeof(*tracker));
    }
}

tcp_retransmission_result_t tcp_retransmission_tracker_record(
    tcp_retransmission_tracker_t *tracker,
    uint8_t protocol,
    const char *source_ip,
    const char *destination_ip,
    uint32_t sequence,
    bool *is_retransmission)
{
    tcp_retransmission_pair_t *pair;

    if (tracker == NULL || source_ip == NULL || destination_ip == NULL ||
        is_retransmission == NULL || source_ip[0] == '\0' ||
        destination_ip[0] == '\0' ||
        strlen(source_ip) >= TCP_RETRANSMISSION_IP_MAX ||
        strlen(destination_ip) >= TCP_RETRANSMISSION_IP_MAX) {
        return TCP_RETRANSMISSION_INVALID_ARGUMENT;
    }

    *is_retransmission = false;
    if (protocol != TCP_RETRANSMISSION_PROTOCOL) {
        return TCP_RETRANSMISSION_IGNORED;
    }

    pair = find_pair(tracker, source_ip, destination_ip);
    if (pair == NULL) {
        size_t index;

        if (tracker->active_pairs >= TCP_RETRANSMISSION_MAX_PAIRS) {
            return TCP_RETRANSMISSION_CAPACITY_FULL;
        }

        for (index = 0; index < TCP_RETRANSMISSION_MAX_PAIRS; index++) {
            if (!tracker->pairs[index].in_use) {
                pair = &tracker->pairs[index];
                memset(pair, 0, sizeof(*pair));
                (void)strncpy(pair->source_ip, source_ip,
                              sizeof(pair->source_ip) - 1);
                (void)strncpy(pair->destination_ip, destination_ip,
                              sizeof(pair->destination_ip) - 1);
                pair->highest_sequence = sequence;
                pair->in_use = true;
                tracker->active_pairs++;
                break;
            }
        }
    }

    if (pair == NULL) {
        return TCP_RETRANSMISSION_CAPACITY_FULL;
    }

    if (pair->total_packets > 0 && sequence < pair->highest_sequence) {
        *is_retransmission = true;
        pair->retransmitted_packets++;
    }
    if (sequence > pair->highest_sequence) {
        pair->highest_sequence = sequence;
    }
    pair->total_packets++;

    return TCP_RETRANSMISSION_RECORDED;
}

int tcp_retransmission_tracker_get_pair_stats(
    const tcp_retransmission_tracker_t *tracker,
    const char *source_ip,
    const char *destination_ip,
    tcp_retransmission_stats_t *stats)
{
    size_t index;

    if (tracker == NULL || source_ip == NULL || destination_ip == NULL ||
        stats == NULL) {
        return -1;
    }

    memset(stats, 0, sizeof(*stats));
    for (index = 0; index < TCP_RETRANSMISSION_MAX_PAIRS; index++) {
        const tcp_retransmission_pair_t *pair = &tracker->pairs[index];

        if (pair->in_use && strcmp(pair->source_ip, source_ip) == 0 &&
            strcmp(pair->destination_ip, destination_ip) == 0) {
            stats->total_packets = pair->total_packets;
            stats->retransmitted_packets = pair->retransmitted_packets;
            if (pair->total_packets != 0) {
                stats->retransmission_rate_percent =
                    ((double)pair->retransmitted_packets * 100.0) /
                    (double)pair->total_packets;
            }
            return 0;
        }
    }

    return -1;
}

size_t tcp_retransmission_tracker_active_pairs(
    const tcp_retransmission_tracker_t *tracker)
{
    return tracker == NULL ? 0 : tracker->active_pairs;
}

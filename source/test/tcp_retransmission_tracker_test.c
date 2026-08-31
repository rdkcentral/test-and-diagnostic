#include "../NetworkTelemetry/tcp_retransmission_tracker.h"

#include <assert.h>
#include <stdio.h>

static void test_direction_and_rate(void)
{
    tcp_retransmission_tracker_t tracker;
    tcp_retransmission_stats_t stats;
    bool retransmission;

    tcp_retransmission_tracker_init(&tracker);
    assert(tcp_retransmission_tracker_record(&tracker, 6, "192.0.2.1",
                                             "198.51.100.1", 100,
                                             &retransmission) == 0);
    assert(!retransmission);
    assert(tcp_retransmission_tracker_record(&tracker, 6, "192.0.2.1",
                                             "198.51.100.1", 90,
                                             &retransmission) == 0);
    assert(retransmission);
    assert(tcp_retransmission_tracker_record(&tracker, 6, "192.0.2.1",
                                             "198.51.100.1", 110,
                                             &retransmission) == 0);
    assert(!retransmission);
    assert(tcp_retransmission_tracker_record(&tracker, 6, "192.0.2.1",
                                             "198.51.100.1", 100,
                                             &retransmission) == 0);
    assert(retransmission);

    assert(tcp_retransmission_tracker_get_pair_stats(
               &tracker, "192.0.2.1", "198.51.100.1", &stats) == 0);
    assert(stats.total_packets == 4);
    assert(stats.retransmitted_packets == 2);
    assert(stats.retransmission_rate_percent == 50.0);

    assert(tcp_retransmission_tracker_record(&tracker, 6, "198.51.100.1",
                                             "192.0.2.1", 1,
                                             &retransmission) == 0);
    assert(!retransmission);
    assert(tcp_retransmission_tracker_active_pairs(&tracker) == 2);
}

static void test_protocol_filter(void)
{
    tcp_retransmission_tracker_t tracker;
    bool retransmission = true;

    tcp_retransmission_tracker_init(&tracker);
    assert(tcp_retransmission_tracker_record(&tracker, 17, "192.0.2.1",
                                             "198.51.100.1", 1,
                                             &retransmission) == 1);
    assert(!retransmission);
    assert(tcp_retransmission_tracker_record(&tracker, 1, "192.0.2.1",
                                             "198.51.100.1", 1,
                                             &retransmission) == 1);
    assert(tcp_retransmission_tracker_active_pairs(&tracker) == 0);
}

static void test_capacity(void)
{
    tcp_retransmission_tracker_t tracker;
    char source[32];
    bool retransmission;
    size_t index;

    tcp_retransmission_tracker_init(&tracker);
    for (index = 0; index < TCP_RETRANSMISSION_MAX_PAIRS; index++) {
        (void)snprintf(source, sizeof(source), "192.0.2.%zu", index + 1);
        assert(tcp_retransmission_tracker_record(
                   &tracker, 6, source, "198.51.100.1", 1,
                   &retransmission) == 0);
    }
    assert(tcp_retransmission_tracker_active_pairs(&tracker) ==
           TCP_RETRANSMISSION_MAX_PAIRS);
    assert(tcp_retransmission_tracker_record(
               &tracker, 6, "203.0.113.1", "198.51.100.1", 1,
               &retransmission) == 2);

    assert(tcp_retransmission_tracker_record(
               &tracker, 6, "192.0.2.1", "198.51.100.1", 2,
               &retransmission) == 0);
    assert(!retransmission);
}

int main(void)
{
    test_direction_and_rate();
    test_protocol_filter();
    test_capacity();
    puts("tcp_retransmission_tracker_test: PASS");
    return 0;
}

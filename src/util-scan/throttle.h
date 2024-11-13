#ifndef THROTTLE_H
#define THROTTLE_H
#include <stdint.h>

#define _THR_MASK 0xFF

/**
 * NOTE: functions about throttler is not thread safe.
 */
typedef struct RateThrottler {
    double   max_rate;
    double   current_rate;
    double   batch_size;
    unsigned index;

    struct {
        uint64_t timestamp;
        uint64_t packet_count;
    } buckets[_THR_MASK + 1];

    uint64_t test_timestamp;
    uint64_t test_packet_count;

} Throttler;

void throttler_start(Throttler *status, double max_rate);

/**
 * @param throttler throttler that has been started
 * @param count how many packets we have sent
 */
uint64_t throttler_next_batch(Throttler *throttler, uint64_t packet_count);

#endif

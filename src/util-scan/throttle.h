#ifndef THROTTLE_H
#define THROTTLE_H
#include <stdint.h>

#define THR_CACHE                256  /*must be power of 2*/

struct Throttler
{
    double max_rate;
    double current_rate;
    double batch_size;

    unsigned index;

    struct {
        uint64_t timestamp;
        uint64_t packet_count;
    } buckets[THR_CACHE];

    uint64_t test_timestamp;
    uint64_t test_packet_count;

};


void 
throttler_start(struct Throttler *status, double max_rate);

/**
 * @param throttler throttler that has been started
 * @param count how many packets we have sent
*/
uint64_t
throttler_next_batch(struct Throttler *throttler, uint64_t packet_count);

#endif

#ifndef PIXIE_TIMER_H
#define PIXIE_TIMER_H

#include <stdint.h>

/**
 * Get monotonic time for interval calc, in microseconds
 */
uint64_t pixie_gettime(void);

/**
 * Get monotonic time for interval calc, in nanoseconds
 */
uint64_t pixie_nanotime(void);

/**
 * Wait the specified number of microseconds
 */
void pixie_usleep(uint64_t usec);

/**
 * Wait the specified number of milliseconds
 */
void pixie_mssleep(unsigned milliseconds);

int pixie_time_selftest();

#endif

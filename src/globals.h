#ifndef GLOBALS_H
#define GLOBALS_H
#include <time.h>

/******************************************************************************
 * These variables are used(read/update) in many place, especially multiple
 * threads. So we'd better try to keep the thread safe.
 ******************************************************************************/

/**
 * Update just in main thread periodically and read by other threads to know a
 * non-accurate time. We use this to avoid much syscal to time(0). I havn't use
 * thread-safe method for it. And according to Masscan's author: PF_RING doesn't
 * timestamp packets well, so we can't always base time from incoming packets.
 */
extern time_t              global_now;
/**
 * This templateset contains all default packet template and can be used by
 * many modules to create a new packet with some wrapped functions. It is
 * initiated in before scanning and only be read after that. Use copying while
 * using.
 */
extern struct TemplateSet *global_tmplset;
/**
 * These are used for hinting tx/rx threads to finish there work. They are
 * updatet and read by multiple threads. We'd better to get the latest value
 * every time we read. I recommend to update them by atomic operations.
 */
extern unsigned volatile time_to_finish_tx;
extern unsigned volatile time_to_finish_rx;

#endif

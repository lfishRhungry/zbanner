#ifndef RECEIVE_H
#define RECEIVE_H

#include "xconf.h"

/***************************************************************************
 * Correspond to a receive thread.
 ***************************************************************************/
struct RxThread {
    /** This points to the central configuration. Note that it's 'const',
     * meaning that the thread cannot change the contents. That'd be
     * unsafe */
    const struct Xconf *xconf;

    unsigned done_receiving;

    double pt_start;

    uint64_t *total_successed;

    uint64_t *total_failed;

    uint64_t *total_tm_event; /*unhandled fast-timeout event*/

    size_t thread_handle_recv;
};


/***************************************************************************
 *
 * Asynchronous receive thread
 *
 * The transmit and receive threads run independently of each other. There
 * is no record what was transmitted. Instead, the transmit thread sets a
 * "SYN-cookie" in transmitted packets, which the receive thread will then
 * use to match up requests with responses.
 ***************************************************************************/
void
receive_thread(void *v);

#endif
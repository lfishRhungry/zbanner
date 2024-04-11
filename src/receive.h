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

    bool done_receiving;

    double pt_start;

    uint64_t total_tm_event; /*unhandled fast-timeout event*/

    struct rte_ring **handle_q;

    struct rte_ring  *dispatch_q;

    size_t thread_handle_recv;
};


/***************************************************************************
 *
 * Asynchronous receive thread
 *
 ***************************************************************************/
void
receive_thread(void *v);

#endif
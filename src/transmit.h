#ifndef TRANSMIT_H
#define TRANSMIT_H

#include "xconf.h"
#include "util-scan/throttle.h"

/***************************************************************************
 * Correspond to a transmit thread.
 ***************************************************************************/
typedef struct TxThreadConfig {

    const Xconf *xconf;

    unsigned tx_index;

    /**
     * A copy of the master 'index' variable. This is just advisory for
     * other threads, to tell them how far we've gotten.
     */
    volatile uint64_t my_index;

    volatile uint64_t my_repeat;

    bool done_transmitting;

    Throttler throttler[1];

    uint64_t total_sent;

    size_t thread_handle_xmit;
} TxThread;


/***************************************************************************
 *
 * Asynchronous transmit thread
 *
 ***************************************************************************/
void
transmit_thread(void *v); /*aka. scanning_thread() */

#endif
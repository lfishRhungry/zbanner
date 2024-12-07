#ifndef TRANSMIT_H
#define TRANSMIT_H

#include <stdbool.h>
#include <stddef.h>

#include "xconf.h"
#include "util-scan/throttle.h"

/***************************************************************************
 * Correspond to a transmit thread.
 ***************************************************************************/
typedef struct TxThreadConfig {
    /** This points to the central configuration. Note that it's 'const',
     * meaning that the thread cannot change the contents. That'd be
     * unsafe */
    const XConf      *xconf;
    /*unique index of the tx thread that count from 0*/
    unsigned          tx_index;
    /**
     * A copy of the master 'index' variable. This is just advisory for
     * other threads, to tell them how far we've gotten.
     */
    volatile uint64_t my_index;
    /*current repeat count of this tx thread that count from 0 */
    volatile uint64_t my_repeat;
    /*for rate limitation*/
    Throttler         throttler[1];
    /*statistics*/
    uint64_t          total_sent;
    /*thread handler(id for process)*/
    size_t            thread_handle_xmit;
    /*is finished*/
    bool              done_transmitting;
} TxThread;

/***************************************************************************
 *
 * Asynchronous transmit thread
 *
 ***************************************************************************/
void transmit_thread(void *v); /*aka. scanning_thread() */

#endif
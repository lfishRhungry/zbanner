/*

    Event timeout

    This is for the user-mode TCP stack. We need to mark timeouts in the
    future when we'll re-visit a connection/tcb. For example, when we
    send a packet, we need to resend it in the future in case we don't
    get a response.

    This design creates a large "ring" of timeouts, and then cycles
    again and again through the ring. This is a fairly high granularity,
    just has hundreds, thousands, or 10 thousand entries per second.
    (I keep adjusting the granularity up and down). Not that at any
    slot in the ring, there may be entries from the far future.

    NOTE: a big feature of this system is that the structure that tracks
    the timeout is actually held within the TCB structure. In other
    words, each TCB can have one-and-only-one timeout.

    NOTE: a recurring bug is that the TCP code removes a TCB from the
    timeout ring and forgets to put it back somewhere else. Since the
    TCB is cleaned up on a timeout, such TCBs never get cleaned up,
    leading to a memory leak. I keep fixing this bug, then changing the
    code and causing the bug to come back again.
*/
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "event-timeout.h"
#include "../util-out/logger.h"
#include "../util-data/fine-malloc.h"
#include "../util-misc/cross.h"


#define EVENT_TM_SLOTS  1024*1024


/***************************************************************************
 * The timeout system is a circular ring. We move an index around the 
 * ring. At each slot in the ring is a linked-list of all entries at
 * that time index. Because the ring can wrap, not everything at a given
 * entry will be the same timestamp. Therefore, when doing the timeout
 * logic at a slot, we have to doublecheck the actual timestamp, and skip
 * those things that are further in the future.
 ***************************************************************************/
struct Timeouts {
    /**
     * This index is a monotonically increasing number, modulus the slot_count.
     * Every time we check timeouts, we simply move it forward in time.
     */
    uint64_t current_index;

    /**
     * Counts the number of outstanding timeouts. Adding a timeout increments
     * this number, and removing a timeout decrements this number. The
     * program shouldn't exit until this number is zero.
     */
    uint64_t outstanding_count;

    unsigned mask;

    /**
     * The ring of entries, must be power of 2.
     */
    struct TimeoutEntry *slots[EVENT_TM_SLOTS];
};

/***************************************************************************
 ***************************************************************************/
struct Timeouts *
timeouts_create(uint64_t timestamp)
{
    struct Timeouts *timeouts;

    timeouts       = CALLOC(1, sizeof(struct Timeouts));
    timeouts->mask = ARRAY_SIZE(timeouts->slots)-1;

    /*
     * Set the index to the current time. Note that this timestamp is
     * the 'time_t' value multiplied by the number of ticks-per-second,
     * where 'ticks' is something I've defined for scanning. Right now
     * I hard-code in the size of the ticks, but eventually they'll be
     * dynamically resized depending upon the speed of the scan.
     */
    timeouts->current_index = timestamp;


    return timeouts;
}

/***************************************************************************
 * This inserts the timeout entry into the appropriate place in the
 * timeout ring.
 ***************************************************************************/
void
timeouts_add(struct Timeouts *timeouts, struct TimeoutEntry *entry,
             size_t offset, uint64_t timestamp)
{
    unsigned index;

    /* Unlink from wherever the entry came from */
    if (entry->timestamp)
        timeouts->outstanding_count--;
    timeout_unlink(entry);

    if (entry->prev) {
        LOG(LEVEL_WARN, "***CHANGE %d-seconds\n", 
            (int)((timestamp-entry->timestamp)/TICKS_PER_SECOND));
    }

    /* Initialize the new entry */
    entry->timestamp = timestamp;
    entry->offset    = (unsigned)offset;

    /* Link it into it's new location */
    index                  = timestamp & timeouts->mask;
    entry->next            = timeouts->slots[index];
    timeouts->slots[index] = entry;
    entry->prev            = &timeouts->slots[index];
    if (entry->next)
        entry->next->prev = &entry->next;

    timeouts->outstanding_count++;
}

/***************************************************************************
 * Remove the next event that it older than the specified timestamp
 ***************************************************************************/
void *
timeouts_remove(struct Timeouts *timeouts, uint64_t timestamp)
{
    struct TimeoutEntry *entry = NULL;

    /* Search until we find one */
    while (timeouts->current_index <= timestamp) {

        /* Start at the current slot */
        entry = timeouts->slots[timeouts->current_index & timeouts->mask];

        /* enumerate through the linked list until we find a used slot */
        while (entry && entry->timestamp > timestamp)
            entry = entry->next;
        if (entry)
            break;

        /* found nothing at this slot, so move to next slot */
        timeouts->current_index++;
    }

    if (entry == NULL) {
        /* we've caught up to the current time, and there's nothing
         * left to timeout, so return NULL */
        return NULL;
    }

    /* unlink this entry from the timeout system */
    timeouts--;
    timeout_unlink(entry);

    /* return a pointer to the structure holding this entry */
    return ((char*)entry) - entry->offset;
}



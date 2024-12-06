#ifndef EVENT_TIMEOUT_H
#define EVENT_TIMEOUT_H

#include <stdint.h>
#include <stdio.h>
#include <stddef.h> /* offsetof*/
#include <stdbool.h>

typedef struct TimeoutTables Timeouts;

/***************************************************************************
 ***************************************************************************/
typedef struct TimeoutEntry {
    /**
     * In units of 1/16384 of a second. We use power-of-two units here
     * to make the "modulus" operation a simple binary "and".
     * See the TICKS_FROM_TV() macro for getting the timestamp from
     * the current time.
     */
    uint64_t              timestamp;
    /** we build a doubly-linked list */
    struct TimeoutEntry  *next;
    struct TimeoutEntry **prev;
    /** The timeout entry is never allocated by itself, but instead
     * lives inside another data structure. This stores the value of
     * 'offsetof()', so given a pointer to this structure, we can find
     * the original structure that contains it */
    unsigned              offset;
} TmEntry;

/***************************************************************************
 ***************************************************************************/
static inline bool timeout_is_unlinked(const TmEntry *entry) {
    if (entry->prev == NULL || entry->next == NULL)
        return true;
    else
        return false;
}

/***************************************************************************
 ***************************************************************************/
static inline void timeout_unlink(TmEntry *entry) {
    if (entry->prev == NULL && entry->next == NULL)
        return;

    if (entry->prev)
        *(entry->prev) = entry->next;
    if (entry->next)
        entry->next->prev = entry->prev;

    entry->next      = NULL;
    entry->prev      = NULL;
    entry->timestamp = 0;
}

/***************************************************************************
 ***************************************************************************/
static inline void timeout_init(TmEntry *entry) {
    entry->next = NULL;
    entry->prev = NULL;
}

/**
 * Create a timeout subsystem.
 * @param timestamp_now
 *      The current timestamp indicating "now" when the thing starts.
 *      This should be 'time(0) * TICKS_PER_SECOND'.
 */
Timeouts *timeouts_create(uint64_t timestamp_now);

/**
 * Insert the timeout 'entry' into the future location in the timeout
 * ring, as determined by the timestamp.
 * NOTE: It's not insert a new timeout but moving existing entry to future.
 *
 * @param timeouts
 *      A ring of timeouts, with each slot corresponding to a specific
 *      time in the future.
 * @param entry
 *      The entry that we are going to insert into the ring. If it's
 *      already in the ring, it'll be removed from the old location
 *      first before inserting into the new location.
 * @param offset
 *      The 'entry' field above is part of an existing structure. This
 *      tells the offset_of() from the beginning of that structure.
 *      In other words, this tells us the pointer to the object that
 *      that is the subject of the timeout.
 * @param timestamp_expires
 *      When this timeout will expire. This is in terms of internal
 *      ticks, which in units of TICKS_PER_SECOND.
 */
void timeouts_add(Timeouts *timeouts, TmEntry *entry, size_t offset,
                  uint64_t timestamp_expires);

/**
 * Remove an object from the timestamp system that is older than than
 * the specified timestamp. This function must be called repeatedly
 * until it returns NULL to remove all the objects that are older
 * than the given timestamp.
 * @param timeouts
 *      A ring of timeouts. We'll walk the ring until we've caught
 *      up with the current time.
 * @param timestamp_now
 *      Usually, this timestmap will be "now", the current time,
 *      and anything older than this will be aged out.
 * @return
 *      an object older than the specified timestamp, or NULL
 *      if there are no more objects to be found
 */
void *timeouts_remove(Timeouts *timeouts, uint64_t timestamp_now);

/*
 * This macros convert a normal "timeval" structure into the timestamp
 * that we use for timeouts. The timeval structure probably will come
 * from the packets that we are capturing.
 */
#define TICKS_PER_SECOND        (16384ULL)
#define TICKS_FROM_SECS(secs)   ((secs) * TICKS_PER_SECOND)
#define TICKS_FROM_USECS(usecs) ((usecs) / 64ULL)
#define TICKS_FROM_TV(secs, usecs)                                             \
    (TICKS_FROM_SECS(secs) + TICKS_FROM_USECS(usecs))

#endif

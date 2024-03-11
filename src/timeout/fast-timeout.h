#ifndef FAST_TIMEOUT_H
#define FAST_TIMEOUT_H

#include <stdint.h>
#include <stdint.h>
#include <time.h>

#include "../util/lfqueue.h"

struct FHandler {
    time_t            spec;
    lfqueue_t        *queue;
    struct FEntry    *oldest; /*oldest event poped from queue*/
};

struct FTable {
    /**
     * What time spec elapses before now should an event be timeout
    */
    time_t       spec;
    lfqueue_t    queue_t;
};

/**
 * Create a fast-timeout table to manage timeout events
 * 
 * @param table type of fast-timeout table.
 * @param spec What time spec elapses before now should an event be timeout
 * @return fast-timeout table.
*/
void ft_init_table(struct FTable *table, time_t spec);

/**
 * Got a handler from fast-timeout table to add or pop timeout events in one thread.
 * 
 * @param table fast-timeout table.
 * @return fast-timeout table handler.
*/
void ft_init_handler(struct FTable *table, struct FHandler *handler);

/**
 * Add an event to fast-timeout table through the handler.
 * Time of the event will be set with now by the func.
 * So put our event in as fast as we can.
 * 
 * ! Thread Safe.
 * 
 * @param handler a handler of fast-timeout table.
 * @param event event that need to set timeout
 * @param now must be time of now
*/
void ft_add_event(struct FHandler *handler, void *event, time_t now);

/**
 * Pop up an event meets timeout now.
 * We should pop up events until get NULL every time.
 * 
 * !Thread Safe
 * 
 * @param handler a handler of fast-timeout table.
 * @return an event meets timeout or NULL because all events are safe.
*/
void * ft_pop_event(struct FHandler *handler, time_t now);

/**
 * Get event count(with the oldest one)
*/
uint64_t ft_event_count(struct FHandler *handler);

/**
 * Clean up the fast-timeout table handler
*/
void ft_close_handler(struct FHandler *handler);

/**
 * Clean up the fast-timeout table with its entries.
*/
void ft_close_table(struct FTable *table);

#endif
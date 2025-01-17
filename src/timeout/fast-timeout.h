#ifndef FAST_TIMEOUT_H
#define FAST_TIMEOUT_H

#include <stdint.h>
#include <stdint.h>
#include <time.h>

typedef struct FastTmHandler FHandler;
typedef struct FastTmTable   FTable;

/**
 * Create a fast-timeout table to manage timeout events
 *
 * @param table type of fast-timeout table.
 * @param spec What time spec elapses before now should an event be timeout
 * @return fast-timeout table.
 */
FTable *ft_init_table(time_t spec);

/**
 * Got a handler from fast-timeout table to add or pop timeout events in one
 * thread.
 *
 * @param table fast-timeout table.
 * @return fast-timeout table handler.
 */
FHandler *ft_get_handler(FTable *table);

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
void ft_add_event(FHandler *handler, void *event, time_t now);

/**
 * Pop up an event meets timeout now.
 * We should pop up events until get NULL every time.
 *
 * !Thread Safe
 *
 * @param handler a handler of fast-timeout table.
 * @return an event meets timeout or NULL because all events are safe.
 */
void *ft_pop_event(FHandler *handler, time_t now);

/**
 * Get event count(with the oldest one)
 */
uint64_t ft_event_count(FHandler *handler);

/**
 * Clean up the fast-timeout table handler
 */
void ft_close_handler(FHandler *handler);

/**
 * Clean up the fast-timeout table with its entries.
 */
void ft_close_table(FTable *table);

#endif
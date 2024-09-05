/**
 * KLUDGE
 *
 * This is a simple and fast version of event-timeout. All expire time spec of
 * events are the same. So we just use a linked list to save and just pop
 * events from head instead of going around all the nodes.
 *
 * FIXME: It must has a better data sructure and algorithm to handle the
 * timeout event in our complex condition(operating in multi-threads, etc). But
 * I'm lazy to get a new one. I feel tired to fix new bugs in these days...
 */
#include "fast-timeout.h"
#include "../util-data/fine-malloc.h"

typedef struct FastTmEntry FEntry;

struct FastTmHandler {
    time_t     spec;
    lfqueue_t *queue;
    /*oldest event poped from queue*/
    FEntry    *oldest;
};

struct FastTmEntry {
    /*time the Entry was create*/
    time_t timestamp;
    /*point to correspond event or struct*/
    void  *event;
};

struct FastTmTable {
    /*What time spec elapses before now should an event be timeout*/
    time_t    spec;
    lfqueue_t queue_t;
};

FTable *ft_init_table(time_t spec) {
    FTable *table = MALLOC(sizeof(FTable));
    lfqueue_init(&table->queue_t);
    table->spec = spec;

    return table;
}

FHandler *ft_get_handler(FTable *table) {
    FHandler *handler = MALLOC(sizeof(FHandler));
    handler->spec     = table->spec;
    handler->queue    = &table->queue_t;
    handler->oldest   = NULL;

    return handler;
}

void ft_add_event(FHandler *handler, void *event, time_t now) {
    FEntry *entry    = MALLOC(sizeof(FEntry));
    entry->timestamp = now;
    entry->event     = event;

    lfqueue_enq(handler->queue, entry);
}

void *ft_pop_event(FHandler *handler, time_t now) {
    if (!handler->oldest) {
        handler->oldest = lfqueue_deq(handler->queue);
        /*no event*/
        if (!handler->oldest)
            return NULL;
    }

    if (now - handler->oldest->timestamp >= handler->spec) {
        void *ret = handler->oldest->event;
        FREE(handler->oldest);
        return ret;
    }

    return NULL;
}

void ft_close_handler(FHandler *handler) {
    if (handler->oldest) {
        FREE(handler->oldest->event);
        free(handler->oldest);
        handler->oldest = NULL;
    }

    free(handler);
}

void ft_close_table(FTable *table) {
    FEntry *entry = lfqueue_deq(&table->queue_t);
    while (entry) {
        FREE(entry->event);
        free(entry);
        entry = lfqueue_deq(&table->queue_t);
    }
    lfqueue_destroy(&table->queue_t);
    FREE(table);
}

uint64_t ft_event_count(FHandler *handler) {
    uint64_t ret;
    ret = lfqueue_size(handler->queue);
    if (handler->oldest)
        ret++;
    return ret;
}
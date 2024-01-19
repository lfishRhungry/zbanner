#ifndef XTATUS_H
#define XTATUS_H
#include <stdint.h>
#include <time.h>
#include "util/bool.h"

struct Xtatus
{
    struct {
        double clock;
        time_t time;
        uint64_t count;
    } last;
    uint64_t timer;
    unsigned charcount;

    double last_rates[8];
    unsigned last_count;

    unsigned is_infinite:1;

    uint64_t total_tcbs;
    uint64_t total_synacks;
    uint64_t total_syns;
    uint64_t total_responsed;
};


void xtatus_print(struct Xtatus *xtatus, uint64_t count,
    uint64_t max_count, double x,
    uint64_t total_tcbs, uint64_t total_synacks,
    uint64_t total_syns, uint64_t total_responsed,
    uint64_t exiting, bool json_status);
void xtatus_finish(struct Xtatus *xtatus);
void xtatus_start(struct Xtatus *xtatus);


#endif

#ifndef XTATUS_H
#define XTATUS_H
#include <stdint.h>
#include <time.h>
#include "../util-misc/cross.h"

struct Xtatus
{
    struct {
        double   clock;
        time_t   time;
        uint64_t count;
    } last;

    double   last_rates[8];
    unsigned last_count;

    unsigned is_infinite:1;
    unsigned print_queue:1;
    unsigned print_info_num:1;
    unsigned print_tcb:1;
    unsigned print_ft_event:1;

    uint64_t total_successed;
    uint64_t total_sent;
};


void xtatus_print(
    struct Xtatus *xtatus,
    uint64_t       count,
    uint64_t       max_count,
    uint64_t       repeat,
    double         pps,
    double         tx_q_ratio,
    double         rx_q_ratio,
    uint64_t       total_successed,
    uint64_t       total_failed,
    uint64_t       total_info,
    uint64_t       total_sent,
    uint64_t       total_tm_event,
    uint64_t       total_tcb,
    uint64_t       exiting,
    bool           json_status);

void xtatus_finish(struct Xtatus *xtatus);

void xtatus_start(struct Xtatus *xtatus);


#endif

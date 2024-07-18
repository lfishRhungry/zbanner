/*
    Born from Masscan
    Modified by lishRhungry 2024
*/
#ifndef MAS_DEDUP_H
#define MAS_DEDUP_H
#include "../target/target-addr.h"
#include "../util-misc/cross.h"

typedef struct DeduplicateTable DedupTable;

DedupTable *dedup_create(unsigned dedup_win);

void dedup_destroy(DedupTable *table);

bool dedup_is_duplicate(DedupTable *dedup, ipaddress ip_them,
                        unsigned port_them, ipaddress ip_me, unsigned port_me,
                        unsigned type);

#endif

#ifndef DEDUP_H
#define DEDUP_H
#include "../massip/massip-addr.h"
#include "../util-misc/cross.h"

struct DedupTable *
dedup_create(unsigned dedup_win);

void
dedup_destroy(struct DedupTable *table);

bool
dedup_is_duplicate(struct DedupTable *dedup,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me, unsigned type);

#endif

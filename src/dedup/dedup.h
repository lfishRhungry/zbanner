/*
    Originally, I modified dedup funcs from masscan to adapt xtate. But I'm
    confused about the performance between mas-dedup and judy-dedup from ZMap.
    So I decided to let users to enjoy both of them and give you guys the
    freedom of choice.

    Modified by lishRhungry 2024
*/
#ifndef DEDUP_H
#define DEDUP_H
#include "../target/target-addr.h"
#include "../util-misc/cross.h"

#ifndef NOT_FOUND_JUDY
typedef struct cachehash_s Dedup;
#else
typedef struct DeduplicateTable Dedup;
#endif

Dedup *dedup_init(unsigned dedup_win);

void dedup_close(Dedup *dedup);

bool dedup_is_dup(Dedup *dedup, ipaddress ip_them, unsigned port_them,
                  ipaddress ip_me, unsigned port_me, unsigned type);

int dedup_selftest();

#endif

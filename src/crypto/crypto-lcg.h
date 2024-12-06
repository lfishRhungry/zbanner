#ifndef CRYPTO_LCG_H
#define CRYPTO_LCG_H

#include <stdint.h>

void lcg_calculate_constants(uint64_t m, uint64_t *out_a, uint64_t *inout_c,
                             int is_debug);

uint64_t lcg_rand(uint64_t index, uint64_t a, uint64_t c, uint64_t range);

int lcg_selftest();

#endif

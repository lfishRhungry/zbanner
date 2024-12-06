#ifndef CRYPTO_SIPHASH24_H
#define CRYPTO_SIPHASH24_H

#include <stdint.h>
#include <stddef.h>

uint64_t siphash24(const void *in, size_t inlen, const uint64_t key[2]);

int siphash24_selftest();

#endif

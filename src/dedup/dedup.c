/**
 * Born and updated from Masscan
 *
 * Modified by sharkocha 2024
 */
#include "dedup.h"

#include <string.h>
#include <assert.h>

#include "../util-data/fine-malloc.h"
#include "../util-out/logger.h"

#define DEDUP_BUCKET_SIZE 4

struct DedupEntry_IPv4 {
    unsigned ip_them;
    unsigned port_them;
    unsigned ip_me;
    unsigned port_me;
    unsigned type;    /*for more flexible dedup*/
    unsigned repeats; /*increase every time duplicate*/
};

struct DedupEntry_IPv6 {
    ipv6address ip_them;
    ipv6address ip_me;
    unsigned    port_them;
    unsigned    port_me;
    unsigned    type;    /*for more flexible dedup*/
    unsigned    repeats; /*increase every time duplicate*/
};

struct DedupEntry {
    struct DedupEntry_IPv4 entries[DEDUP_BUCKET_SIZE];
    struct DedupEntry_IPv6 entries6[DEDUP_BUCKET_SIZE];
};

/**
 * This is simply the array of entries. We have two arrays, one for IPv4
 * and another for IPv6.
 */
struct DeduplicateTable {
    /*num of entries(power of 2) - 1*/
    unsigned          mask;
    struct DedupEntry all_entries[0];
};

/**
 * We use the FNv1a hash algorithm, which starts with this seed value.
 */
const unsigned fnv1a_seed = 0x811C9DC5; /* 2166136261 */

/**
 * Hash one byte, the other hash functions of multiple bytes call this
 * function.
 * @param hash
 *      The current hash value that we keep updating as we repeatedly
 *      call this function, or the `fnv1a_seed   value on the first call to
 *      this function.
 */
static inline unsigned _fnv1a(unsigned char c, unsigned hash) {
    const unsigned prime = 0x01000193; /* 16777619 */
    return (c ^ hash) * prime;
}

static unsigned _fnv1a_string(const void *v_buf, size_t length, unsigned hash) {
    const unsigned char *buf = (const unsigned char *)v_buf;
    size_t               i;
    for (i = 0; i < length; i++)
        hash = _fnv1a(buf[i], hash);
    return hash;
}

static inline unsigned _fnv1a_short(unsigned data, unsigned hash) {
    hash = _fnv1a((data >> 0) & 0xFF, hash);
    hash = _fnv1a((data >> 8) & 0xFF, hash);
    return hash;
}
static inline unsigned _fnv1a_longlong(unsigned long long data, unsigned hash) {
    return _fnv1a_string(&data, 8, hash);
}

/**
 * Create a new table, which means simply allocating the object
 * and setting it to zero.
 */
DedupTable *dedup_create(unsigned dedup_win) {
    // transfer dedup_win to real entries count
    unsigned entries_count =
        dedup_win / DEDUP_BUCKET_SIZE > 0 ? dedup_win / DEDUP_BUCKET_SIZE : 1;

    /* Find nearest power of 2 to entry count */
    {
        size_t new_entry_count;
        new_entry_count = 1;
        while (new_entry_count < entries_count) {
            new_entry_count *= 2;
            if (new_entry_count == 0) {
                new_entry_count = (1 << 24);
                break;
            }
        }
        // if (new_entry_count > (1<<24))
        //     new_entry_count = (1<<24);
        // if (new_entry_count < (1<<10))
        //     new_entry_count = (1<<10);
        entries_count = new_entry_count;
    }

    DedupTable *dedup;
    dedup       = CALLOC(1, sizeof(DedupTable) +
                                sizeof(struct DedupEntry) * entries_count);
    dedup->mask = entries_count - 1;

    return dedup;
}

/**
 * There's nothing special we need to do to free the structure
 * since it's all contained in the single allocation.
 */
void dedup_destroy(DedupTable *dedup) { FREE(dedup); }

/**
 * Create a hash of the IPv6 socket. This doesn't have to be
 * cryptographically secure, so we are going to use the FNv1a algorithm.
 */
static inline unsigned _dedup_hash_ipv6(ipaddress ip_them, unsigned port_them,
                                        ipaddress ip_me, unsigned port_me,
                                        unsigned type) {
    unsigned hash = fnv1a_seed;
    hash          = _fnv1a_longlong(ip_them.ipv6.hi, hash);
    hash          = _fnv1a_longlong(ip_them.ipv6.lo, hash);
    hash          = _fnv1a_short(port_them, hash);
    hash          = _fnv1a_longlong(ip_me.ipv6.hi, hash);
    hash          = _fnv1a_longlong(ip_me.ipv6.lo, hash);
    hash          = _fnv1a_short(port_me, hash);
    hash          = _fnv1a_short(type, hash);
    return hash;
}

/**
 * If two IPv6 addresses are equal.
 */
static inline int _is_equal6(ipv6address lhs, ipv6address rhs) {
    return lhs.hi == rhs.hi && lhs.lo == rhs.lo;
}

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif

/**
 * Swap two addresses in the table. This uses the classic XOR trick
 * rather than using a swap variable.
 */
static inline void _swap6(struct DedupEntry_IPv6 *lhs,
                          struct DedupEntry_IPv6 *rhs) {
    lhs->ip_them.hi ^= rhs->ip_them.hi;
    lhs->ip_them.lo ^= rhs->ip_them.lo;
    lhs->port_them ^= rhs->port_them;
    lhs->ip_me.hi ^= rhs->ip_me.hi;
    lhs->ip_me.lo ^= rhs->ip_me.lo;
    lhs->port_me ^= rhs->port_me;
    lhs->type ^= rhs->type;

    rhs->ip_them.hi ^= lhs->ip_them.hi;
    rhs->ip_them.lo ^= lhs->ip_them.lo;
    rhs->port_them ^= lhs->port_them;
    rhs->ip_me.hi ^= lhs->ip_me.hi;
    rhs->ip_me.lo ^= lhs->ip_me.lo;
    rhs->port_me ^= lhs->port_me;
    rhs->type ^= lhs->type;

    lhs->ip_them.hi ^= rhs->ip_them.hi;
    lhs->ip_them.lo ^= rhs->ip_them.lo;
    lhs->port_them ^= rhs->port_them;
    lhs->ip_me.hi ^= rhs->ip_me.hi;
    lhs->ip_me.lo ^= rhs->ip_me.lo;
    lhs->port_me ^= rhs->port_me;
    lhs->type ^= rhs->type;
}

#ifdef __clang__
#pragma clang diagnostic pop
#endif

/**
 * This implements the same algorithm as for IPv4 addresses, but for
 * IPv6 addresses instead.
 * @return count of repeats
 */
static unsigned _dedup_is_dup_ipv6(DedupTable *dedup, ipaddress ip_them,
                                   unsigned port_them, ipaddress ip_me,
                                   unsigned port_me, unsigned type) {
    unsigned                hash;
    struct DedupEntry_IPv6 *bucket;
    unsigned                i;
    unsigned                repeats;

    hash   = _dedup_hash_ipv6(ip_them, port_them, ip_me, port_me, type);
    bucket = dedup->all_entries[hash & dedup->mask].entries6;

    /* If we find the entry in our table, move it to the front, so
     * that it won't be aged out as quickly. We keep prepending new
     * addresses to front, aging older addresses that haven't been
     * seen in a while. */
    for (i = 0; i < 4; i++) {
        if (_is_equal6(bucket[i].ip_them, ip_them.ipv6) &&
            bucket[i].port_them == port_them &&
            _is_equal6(bucket[i].ip_me, ip_me.ipv6) &&
            bucket[i].port_me == port_me && bucket[i].type == type) {

            /*record increased repeats*/
            repeats = bucket[i].repeats + 1;

            /* move to head of list so constant repeats get attention */
            if (i > 0) {
                // _swap6(&bucket[0], &bucket[i]);
                memmove(bucket + 1, bucket, i * sizeof(*bucket));
                bucket[0].ip_them.hi = ip_them.ipv6.hi;
                bucket[0].ip_them.lo = ip_them.ipv6.lo;
                bucket[0].port_them  = (unsigned short)port_them;
                bucket[0].ip_me.hi   = ip_me.ipv6.hi;
                bucket[0].ip_me.lo   = ip_me.ipv6.lo;
                bucket[0].port_me    = (unsigned short)port_me;
                bucket[0].type       = type;
            }

            /*save and return repeats*/
            bucket[0].repeats = repeats;
            return repeats;
        }
    }

    /* We didn't find it, so add it to our list. This will push
     * older entries at this bucket off the list
     * NOTE the paramter order of memmove
     */
    memmove(bucket + 1, bucket, (DEDUP_BUCKET_SIZE - 1) * sizeof(*bucket));
    bucket[0].ip_them.hi = ip_them.ipv6.hi;
    bucket[0].ip_them.lo = ip_them.ipv6.lo;
    bucket[0].port_them  = (unsigned short)port_them;
    bucket[0].ip_me.hi   = ip_me.ipv6.hi;
    bucket[0].ip_me.lo   = ip_me.ipv6.lo;
    bucket[0].port_me    = (unsigned short)port_me;
    bucket[0].type       = type;
    bucket[0].repeats    = 0;

    return 0;
}

/**
 * Create a hash of the IPv6 socket. This doesn't have to be
 * cryptographically secure, so we are going to use the FNv1a algorithm.
 */
static inline unsigned _dedup_hash_ipv4(ipaddress ip_them, unsigned port_them,
                                        ipaddress ip_me, unsigned port_me,
                                        unsigned type) {
    unsigned hash = fnv1a_seed;
    hash          = _fnv1a_short(ip_them.ipv4, hash);
    hash          = _fnv1a_short(port_them, hash);
    hash          = _fnv1a_short(ip_me.ipv4, hash);
    hash          = _fnv1a_short(port_me, hash);
    hash          = _fnv1a_short(type, hash);
    return hash;
}

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif

/**
 * Swap two addresses in the table. This uses the classic XOR trick
 * rather than using a swap variable.
 */
static inline void _swap4(struct DedupEntry_IPv4 *lhs,
                          struct DedupEntry_IPv4 *rhs) {
    lhs->ip_them ^= rhs->ip_them;
    lhs->port_them ^= rhs->port_them;
    lhs->ip_me ^= rhs->ip_me;
    lhs->port_me ^= rhs->port_me;
    lhs->type ^= rhs->type;

    rhs->ip_them ^= lhs->ip_them;
    rhs->port_them ^= lhs->port_them;
    rhs->ip_me ^= lhs->ip_me;
    rhs->port_me ^= lhs->port_me;
    rhs->type ^= lhs->type;

    lhs->ip_them ^= rhs->ip_them;
    lhs->port_them ^= rhs->port_them;
    lhs->ip_me ^= rhs->ip_me;
    lhs->port_me ^= rhs->port_me;
    lhs->type ^= rhs->type;
}

#ifdef __clang__
#pragma clang diagnostic pop
#endif

/***************************************************************************
 * @return count of repeats
 ***************************************************************************/
static unsigned _dedup_is_dup_ipv4(DedupTable *dedup, ipaddress ip_them,
                                   unsigned port_them, ipaddress ip_me,
                                   unsigned port_me, unsigned type) {
    unsigned                hash;
    struct DedupEntry_IPv4 *bucket;
    unsigned                i;
    unsigned                repeats;

    hash   = _dedup_hash_ipv4(ip_them, port_them, ip_me, port_me, type);
    bucket = dedup->all_entries[hash & dedup->mask].entries;

    /* If we find the entry in our table, move it to the front, so
     * that it won't be aged out as quickly. We keep prepending new
     * addresses to front, aging older addresses that haven't been
     * seen in a while. */
    for (i = 0; i < 4; i++) {
        if (bucket[i].ip_them == ip_them.ipv4 &&
            bucket[i].port_them == port_them && bucket[i].ip_me == ip_me.ipv4 &&
            bucket[i].port_me == port_me && bucket[i].type == type) {

            /*record increased repeats*/
            repeats = bucket[i].repeats + 1;

            /* move to head of list so constant repeats get attention */
            if (i > 0) {
                // _swap4(&bucket[0], &bucket[i]);
                memmove(bucket + 1, bucket, i * sizeof(*bucket));
                bucket[0].ip_them   = ip_them.ipv4;
                bucket[0].port_them = port_them;
                bucket[0].ip_me     = ip_me.ipv4;
                bucket[0].port_me   = port_me;
                bucket[0].type      = type;
            }

            /*save and return repeats*/
            bucket[0].repeats = repeats;
            return repeats;
        }
    }

    /* We didn't find it, so add it to our list. This will push
     * older entries at this bucket off the list
     * NOTE the paramter order of memmove
     */
    memmove(bucket + 1, bucket, (DEDUP_BUCKET_SIZE - 1) * sizeof(*bucket));
    bucket[0].ip_them   = ip_them.ipv4;
    bucket[0].port_them = port_them;
    bucket[0].ip_me     = ip_me.ipv4;
    bucket[0].port_me   = port_me;
    bucket[0].type      = type;
    bucket[0].repeats   = 0;

    return 0;
}

/***************************************************************************
 ***************************************************************************/
unsigned dedup_is_dup(DedupTable *dedup, ipaddress ip_them, unsigned port_them,
                      ipaddress ip_me, unsigned port_me, unsigned type) {
    if (ip_them.version == 6)
        return _dedup_is_dup_ipv6(dedup, ip_them, port_them, ip_me, port_me,
                                  type);
    else
        return _dedup_is_dup_ipv4(dedup, ip_them, port_them, ip_me, port_me,
                                  type);
}

/**
 * My own deterministic rand() function for testing this module
 */
static unsigned _rand(unsigned *seed) {
    static const unsigned a = 214013;
    static const unsigned c = 2531011;

    *seed = (*seed) * a + c;
    return (*seed) >> 16 & 0x7fff;
}

/*
 * Provide a simple unit test for this module.
 *
 * This is a pretty lame test. I'm going to generate
 * a set of random addresses, tweaked so that they aren't
 * too random, so that I get around 30 to 50 expected
 * duplicates. If I get zero duplicates, or if I get too
 * many duplicates in the test, then I know it's failed.
 *
 * This is in no way a reliable test that deterministically
 * tests the functionality. It's a crappy non-deterministic
 * test.
 *
 * We also do a simple deterministic test, but this still
 * is insufficient testing how duplicates age out and such.
 */
int dedup_selftest() {
    DedupTable *dedup;
    unsigned    seed = 0;
    size_t      i;
    unsigned    found_match = 0;
    unsigned    line        = 0;

    dedup = dedup_create(1000000);

    /* Deterministic test.
     *
     * The first time we check on a socket combo, there should
     * be no duplicate. The second time we check, however, there should
     * be a duplicate.
     */
    {
        ipaddress ip_me;
        ipaddress ip_them;
        unsigned  port_me;
        unsigned  port_them;
        unsigned  type;

        ip_me.version   = 4;
        ip_them.version = 4;
        ip_me.ipv4      = 0x12345678;
        ip_them.ipv4    = 0xabcdef0;
        port_me         = 0x1234;
        port_them       = 0xfedc;
        type            = 0x8967;

        if (dedup_is_dup(dedup, ip_them, port_them, ip_me, port_me, type)) {
            line = __LINE__;
            goto fail;
        }
        if (!dedup_is_dup(dedup, ip_them, port_them, ip_me, port_me, type)) {
            line = __LINE__;
            goto fail;
        }

        ip_me.version   = 6;
        ip_them.version = 6;
        ip_me.ipv6.hi   = 0x12345678;
        ip_me.ipv6.lo   = 0x12345678;
        ip_them.ipv6.hi = 0xabcdef0;
        ip_them.ipv6.lo = 0xabcdef0;
        type            = 0x7654;

        if (dedup_is_dup(dedup, ip_them, port_them, ip_me, port_me, type)) {
            line = __LINE__;
            goto fail;
        }
        if (!dedup_is_dup(dedup, ip_them, port_them, ip_me, port_me, type)) {
            ipaddress_formatted_t fmt1 = ipaddress_fmt(ip_them);
            ipaddress_formatted_t fmt2 = ipaddress_fmt(ip_me);
            LOG(LEVEL_ERROR, "(%s):%u -> (%s):%u\n", fmt1.string, port_them,
                fmt2.string, port_me);
            line = __LINE__;
            goto fail;
        }
    }

    /* Test IPv4 addresses */
    for (i = 0; i < 100000; i++) {
        ipaddress ip_them;
        unsigned  port_them;
        ipaddress ip_me;
        unsigned  port_me;
        unsigned  type;

        ip_them.version = 4;
        ip_me.version   = 4;

        /* Instead of completely random numbers over the entire
         * range, each port/IP is restricted to just 512
         * random combinations. This should statistically
         * give us around 10 matches*/
        ip_them.ipv4 = _rand(&seed) & 0x1FF;
        port_them    = _rand(&seed) & 0x1FF;
        ip_me.ipv4   = _rand(&seed) & 0xFF800000;
        port_me      = _rand(&seed) & 0xFF80;
        type         = _rand(&seed) & 0B111;

        if (dedup_is_dup(dedup, ip_them, port_them, ip_me, port_me, type)) {
            found_match++;
        }
    }

    if (found_match == 0 || found_match > 200) {
        line = __LINE__;
        goto fail;
    }

    /* Now do IPv6 */
    found_match = 0;
    seed        = 0;

    /* Test IPv4 addresses */
    for (i = 0; i < 100000; i++) {
        ipaddress ip_them;
        unsigned  port_them;
        ipaddress ip_me;
        unsigned  port_me;
        unsigned  type;

        ip_them.version = 6;
        ip_me.version   = 6;

        /* Instead of completely random numbers over the entire
         * range, each port/IP is restricted to just 512
         * random combinations. This should statistically
         * give us around 10 matches*/
        ip_me.ipv6.hi   = _rand(&seed) & 0xFF800000;
        ip_them.ipv6.lo = _rand(&seed) & 0x1FF;
        port_me         = _rand(&seed) & 0xFF80;
        port_them       = _rand(&seed) & 0x1FF;
        type            = _rand(&seed) & 0B111;

        if (dedup_is_dup(dedup, ip_them, port_them, ip_me, port_me, type)) {
            found_match++;
        }
    }

    /* The result should be same as for IPv4, around 30 matches found. */
    if (found_match == 0 || found_match > 200) {
        line = __LINE__;
        goto fail;
    }

    dedup_destroy(dedup);

    /* All tests have passed */
    return 0; /* success :) */

fail:
    LOG(LEVEL_ERROR, "(%s) selftest failed, file=%s, line=%u\n", __func__,
        __FILE__, line);
    return 1;
}
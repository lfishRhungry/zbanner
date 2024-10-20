#include "dedup.h"
#include "mas-dedup.h"
#include "cachehash.h"
#include "../util-out/logger.h"

struct DedupItem_IPv4 {
    unsigned    type;
    ipv4address ip_them;
    ipv4address ip_me;
    unsigned    port_them;
    unsigned    port_me;
};

struct DedupItem_IPv6 {
    unsigned    type;
    ipv6address ip_them;
    ipv6address ip_me;
    unsigned    port_them;
    unsigned    port_me;
};

Dedup *dedup_init(unsigned dedup_win) {
#ifndef NOT_FOUND_JUDY
    return cachehash_init(dedup_win, NULL);
#else
    return dedup_create(dedup_win);
#endif
}

void dedup_close(Dedup *dedup) {
#ifndef NOT_FOUND_JUDY
    cachehash_free(dedup, NULL);
#else
    dedup_destroy(dedup);
#endif
}

bool dedup_is_dup(Dedup *dedup, ipaddress ip_them, unsigned port_them,
                  ipaddress ip_me, unsigned port_me, unsigned type) {
#ifndef NOT_FOUND_JUDY
    /**
     * Cachehash(Judy) from ZMap got hash from a complete struct. This would be
     * confused for our ipaddress which could be ipv4 and ipv6. And we couldn't
     * promise the zero memory of ipv4 part from ipv6 ipaddress. So a simple
     * way is to truncate the meaningful part of ipaddress and put them together
     * for cachehass(Judy). That is:
     */
    if (ip_them.version == 4) {
        struct DedupItem_IPv4 item = {.ip_them   = ip_them.ipv4,
                                      .port_them = port_them,
                                      .ip_me     = ip_me.ipv4,
                                      .port_me   = port_me,
                                      .type      = type};
        if (cachehash_get(dedup, &item, sizeof(struct DedupItem_IPv4))) {
            return true;
        } else {
            cachehash_put(dedup, &item, sizeof(struct DedupItem_IPv4),
                          (void *)1);
            return false;
        }
    } else if (ip_them.version == 6) {
        struct DedupItem_IPv6 item = {.ip_them   = ip_them.ipv6,
                                      .port_them = port_them,
                                      .ip_me     = ip_me.ipv6,
                                      .port_me   = port_me,
                                      .type      = type};
        if (cachehash_get(dedup, &item, sizeof(struct DedupItem_IPv6))) {
            return true;
        } else {
            cachehash_put(dedup, &item, sizeof(struct DedupItem_IPv6),
                          (void *)1);
            return false;
        }
    }

    return false;

#else
    return dedup_is_duplicate(dedup, ip_them, port_them, ip_me, port_me, type);
#endif
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
    Dedup   *dedup;
    unsigned seed = 0;
    size_t   i;
    unsigned found_match = 0;
    unsigned line        = 0;

    dedup = dedup_init(1000000);

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

    dedup_close(dedup);

    /* All tests have passed */
    return 0; /* success :) */

fail:
    LOG(LEVEL_ERROR, "(dedup) selftest failed, file=%s, line=%u\n", __FILE__,
        line);
    return 1;
}
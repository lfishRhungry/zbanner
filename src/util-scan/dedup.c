#include "dedup.h"
#include "../util-data/fine-malloc.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../massip/cookie.h"

#define DEDUP_BUCKET_SIZE 4

struct DedupEntry_IPv4
{
    unsigned ip_them;
    unsigned port_them;
    unsigned ip_me;
    unsigned port_me;
    unsigned type; /*for more flexible dedup*/
};

struct DedupEntry_IPv6
{
    ipv6address    ip_them;
    ipv6address    ip_me;
    unsigned short port_them;
    unsigned short port_me;
    unsigned       type; /*for more flexible dedup*/
};

struct DedupEntry
{
    struct DedupEntry_IPv4 entries[DEDUP_BUCKET_SIZE];
    struct DedupEntry_IPv6 entries6[DEDUP_BUCKET_SIZE];
};

/**
 * This is simply the array of entries. We have two arrays, one for IPv4
 * and another for IPv6.
 */
struct DedupTable
{
    /*num of entries(power of 2) - 1*/
    unsigned mask;
    struct DedupEntry all_entries[0];
};

/**
 * We use the FNv1a hash algorithm, which starts with this seed value.
 */
const unsigned fnv1a_seed  = 0x811C9DC5; /* 2166136261 */

/**
 * Hash one byte, the other hash functions of multiple bytes call this function.
 * @param hash
 *      The current hash value that we keep updating as we repeatedly
 *      call this function, or the `fnv1a_seed   value on the first call to
 *      this function.
 */
static inline unsigned fnv1a(unsigned char c, unsigned hash)
{
  const unsigned prime = 0x01000193; /* 16777619 */
  return (c ^ hash) * prime;
}

static unsigned fnv1a_string(const void *v_buf, size_t length, unsigned hash)
{
    const unsigned char *buf = (const unsigned char *)v_buf;
    size_t i;
    for (i=0; i<length; i++)
        hash = fnv1a(buf[i], hash);
    return hash;
}

static inline unsigned fnv1a_short(unsigned data, unsigned hash)
{
    hash = fnv1a((data>>0)&0xFF, hash);
    hash = fnv1a((data>>8)&0xFF, hash);
    return hash;
}
static inline unsigned fnv1a_longlong(unsigned long long data, unsigned hash)
{
    return fnv1a_string(&data, 8, hash);
}

/**
 * Create a new table, which means simply allocating the object
 * and setting it to zero.
 */
struct DedupTable *
dedup_create(unsigned dedup_win)
{
    //transfer dedup_win to real entries count
    unsigned entries_count =
        dedup_win/DEDUP_BUCKET_SIZE>0?dedup_win/DEDUP_BUCKET_SIZE:1;

    /* Find nearest power of 2 to entry count */
    {
        size_t new_entry_count;
        new_entry_count = 1;
        while (new_entry_count < entries_count) {
            new_entry_count *= 2;
            if (new_entry_count == 0) {
                new_entry_count = (1<<24);
                break;
            }
        }
        // if (new_entry_count > (1<<24))
        //     new_entry_count = (1<<24);
        // if (new_entry_count < (1<<10))
        //     new_entry_count = (1<<10);
        entries_count = new_entry_count;
    }

    struct DedupTable *dedup;
    dedup = CALLOC(1,
        sizeof(struct DedupTable) + sizeof(struct DedupEntry) * entries_count);
    dedup->mask = entries_count - 1;

    return dedup;
}

/**
 * There's nothing special we need to do to free the structure
 * since it's all contained in the single allocation.
 */
void
dedup_destroy(struct DedupTable *dedup)
{
    free(dedup);
}

/**
 * Create a hash of the IPv6 socket. This doesn't have to be
 * cryptographically secure, so we are going to use the FNv1a algorithm.
 */
static inline unsigned
dedup_hash_ipv6(ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me, unsigned type)
{
    unsigned hash = fnv1a_seed;
    hash = fnv1a_longlong(ip_them.ipv6.hi, hash);
    hash = fnv1a_longlong(ip_them.ipv6.lo, hash);
    hash = fnv1a_short(port_them, hash);
    hash = fnv1a_longlong(ip_me.ipv6.hi, hash);
    hash = fnv1a_longlong(ip_me.ipv6.lo, hash);
    hash = fnv1a_short(port_me, hash);
    hash = fnv1a_short(type, hash);
    return hash;
}

/**
 * If two IPv6 addresses are equal.
 */
static inline int
is_equal6(ipv6address lhs, ipv6address rhs)
{
    return lhs.hi == rhs.hi && lhs.lo == rhs.lo;
}

/**
 * Swap two addresses in the table. This uses the classic XOR trick
 * rather than using a swap variable.
 */
static inline void
swap6(struct DedupEntry_IPv6 *lhs, struct DedupEntry_IPv6 *rhs)
{
    lhs->ip_them.hi ^= rhs->ip_them.hi;
    lhs->ip_them.lo ^= rhs->ip_them.lo;
    lhs->port_them  ^= rhs->port_them;
    lhs->ip_me.hi   ^= rhs->ip_me.hi;
    lhs->ip_me.lo   ^= rhs->ip_me.lo;
    lhs->port_me    ^= rhs->port_me;
    lhs->type       ^= rhs->type;

    rhs->ip_them.hi ^= lhs->ip_them.hi;
    rhs->ip_them.lo ^= lhs->ip_them.lo;
    rhs->port_them  ^= lhs->port_them;
    rhs->ip_me.hi   ^= lhs->ip_me.hi;
    rhs->ip_me.lo   ^= lhs->ip_me.lo;
    rhs->port_me    ^= lhs->port_me;
    rhs->type       ^= lhs->type;

    lhs->ip_them.hi ^= rhs->ip_them.hi;
    lhs->ip_them.lo ^= rhs->ip_them.lo;
    lhs->port_them  ^= rhs->port_them;
    lhs->ip_me.hi   ^= rhs->ip_me.hi;
    lhs->ip_me.lo   ^= rhs->ip_me.lo;
    lhs->port_me    ^= rhs->port_me;
    lhs->type       ^= rhs->type;
}

/**
 * This implements the same algorithm as for IPv4 addresses, but for
 * IPv6 addresses instead.
 */
static unsigned
dedup_is_duplicate_ipv6(struct DedupTable *dedup,
                   ipaddress ip_them, unsigned port_them,
                   ipaddress ip_me, unsigned port_me, unsigned type)
{
    unsigned hash;
    struct DedupEntry_IPv6 *bucket;
    unsigned i;

    hash   = dedup_hash_ipv6(ip_them, port_them, ip_me, port_me, type);
    bucket = dedup->all_entries[hash & dedup->mask].entries6;

    /* If we find the entry in our table, move it to the front, so
     * that it won't be aged out as quickly. We keep prepending new
     * addresses to front, aging older addresses that haven't been
     * seen in a while. */
    for (i = 0; i < 4; i++) {
        if (is_equal6(bucket[i].ip_them, ip_them.ipv6) && bucket[i].port_them == port_them
            && is_equal6(bucket[i].ip_me, ip_me.ipv6) && bucket[i].port_me == port_me
            && bucket[i].type == type) {
            /* move to head of list so constant repeats get attention */
            if (i > 0) {
                // swap6(&bucket[0], &bucket[i]);
                memmove(bucket+1, bucket, i*sizeof(*bucket));
                bucket[0].ip_them.hi = ip_them.ipv6.hi;
                bucket[0].ip_them.lo = ip_them.ipv6.lo;
                bucket[0].port_them  = (unsigned short)port_them;
                bucket[0].ip_me.hi   = ip_me.ipv6.hi;
                bucket[0].ip_me.lo   = ip_me.ipv6.lo;
                bucket[0].port_me    = (unsigned short)port_me;
                bucket[0].type       = type;
            }
            return 1;
        }
    }

    /* We didn't find it, so add it to our list. This will push
     * older entries at this bucket off the list
     * NOTE the paramter order of memmove
     */
    memmove(bucket+1, bucket, 3*sizeof(*bucket));
    bucket[0].ip_them.hi = ip_them.ipv6.hi;
    bucket[0].ip_them.lo = ip_them.ipv6.lo;
    bucket[0].port_them  = (unsigned short)port_them;
    bucket[0].ip_me.hi   = ip_me.ipv6.hi;
    bucket[0].ip_me.lo   = ip_me.ipv6.lo;
    bucket[0].port_me    = (unsigned short)port_me;
    bucket[0].type       = type;

    return 0;

}

/**
 * Create a hash of the IPv6 socket. This doesn't have to be
 * cryptographically secure, so we are going to use the FNv1a algorithm.
 */
static inline unsigned
dedup_hash_ipv4(ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me, unsigned type)
{
    unsigned hash = fnv1a_seed;
    hash = fnv1a_short(ip_them.ipv4, hash);
    hash = fnv1a_short(port_them, hash);
    hash = fnv1a_short(ip_me.ipv4, hash);
    hash = fnv1a_short(port_me, hash);
    hash = fnv1a_short(type, hash);
    return hash;
}

/**
 * Swap two addresses in the table. This uses the classic XOR trick
 * rather than using a swap variable.
 */
static inline void
swap4(struct DedupEntry_IPv4 *lhs, struct DedupEntry_IPv4 *rhs)
{
    lhs->ip_them   ^= rhs->ip_them;
    lhs->port_them ^= rhs->port_them;
    lhs->ip_me     ^= rhs->ip_me;
    lhs->port_me   ^= rhs->port_me;
    lhs->type      ^= rhs->type;

    rhs->ip_them   ^= lhs->ip_them;
    rhs->port_them ^= lhs->port_them;
    rhs->ip_me     ^= lhs->ip_me;
    rhs->port_me   ^= lhs->port_me;
    rhs->type      ^= lhs->type;

    lhs->ip_them   ^= rhs->ip_them;
    lhs->port_them ^= rhs->port_them;
    lhs->ip_me     ^= rhs->ip_me;
    lhs->port_me   ^= rhs->port_me;
    lhs->type      ^= rhs->type;
}

/***************************************************************************
 ***************************************************************************/
static unsigned
dedup_is_duplicate_ipv4(struct DedupTable *dedup,
                   ipaddress ip_them, unsigned port_them,
                   ipaddress ip_me, unsigned port_me, unsigned type)
{
    unsigned hash;
    struct DedupEntry_IPv4 *bucket;
    unsigned i;

    hash   = dedup_hash_ipv4(ip_them, port_them, ip_me, port_me, type);
    bucket = dedup->all_entries[hash & dedup->mask].entries;

    /* If we find the entry in our table, move it to the front, so
     * that it won't be aged out as quickly. We keep prepending new
     * addresses to front, aging older addresses that haven't been
     * seen in a while. */
    for (i = 0; i < 4; i++) {
        if (bucket[i].ip_them == ip_them.ipv4 && bucket[i].port_them == port_them
            && bucket[i].ip_me == ip_me.ipv4 && bucket[i].port_me == port_me
            && bucket[i].type == type) {
            /* move to head of list so constant repeats get attention */
            if (i > 0) {
                // swap4(&bucket[0], &bucket[i]);
                memmove(bucket+1, bucket, i*sizeof(*bucket));
                bucket[0].ip_them   = ip_them.ipv4;
                bucket[0].port_them = port_them;
                bucket[0].ip_me     = ip_me.ipv4;
                bucket[0].port_me   = port_me;
                bucket[0].type      = type;
            }
            return 1;
        }
    }

    /* We didn't find it, so add it to our list. This will push
     * older entries at this bucket off the list
     * NOTE the paramter order of memmove
     */
    memmove(bucket+1, bucket, 3*sizeof(*bucket));
    bucket[0].ip_them   = ip_them.ipv4;
    bucket[0].port_them = port_them;
    bucket[0].ip_me     = ip_me.ipv4;
    bucket[0].port_me   = port_me;
    bucket[0].type      = type;

    return 0;

}

/***************************************************************************
 ***************************************************************************/
unsigned
dedup_is_duplicate(struct DedupTable *dedup,
                   ipaddress ip_them, unsigned port_them,
                   ipaddress ip_me, unsigned port_me, unsigned type)
{
    if (ip_them.version == 6)
        return dedup_is_duplicate_ipv6(dedup, ip_them, port_them,
            ip_me, port_me, type);
    else
        return dedup_is_duplicate_ipv4(dedup, ip_them, port_them,
            ip_me, port_me, type);
}

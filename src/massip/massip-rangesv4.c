/*
    IPv4 and port ranges
 
 This is one of the more integral concepts internally.
 We combine all the input addresses and address ranges into a sorted list
 of 'target' IP addresses. This allows us to enumerate all the addresses
 in order by incrementing a simple index. It is that index that we randomize
 in order to produce random output, but internally, everything is sorted.
 
 Sorting the list allows us to remove duplicates. It also allows us to
 apply the 'excludes' directly to the input list. In other words, other
 scanners typically work by selecting an IP address at random, then checking
 to see if it's been excluded, then skipping it. In this scanner, however,
 we remove all the excluded address from the targets list before we start
 scanning.
 
 This module has been tuned to support mass lists of millions of target
 IPv4 addresses and excludes. This has required:
    - a fast way to parse the address from a file (see range-file.c)
    - fast sort (just using qsort() from the standard C library)
    - fast application of exludes, using an optimal O(n + m) linear
      algorithm, where 'n' is the number of targets, and 'm' is the
      number of excluded ranges.
 Large lists can still take a bit to process. On a fast server with
 7-million input ranges/addresses and 5000 exclude ranges/addresses,
 it takes almost 3 seconds to process everything before starting.
 
*/
#include "massip-rangesv4.h"
#include "massip-port.h"
#include "../util-out/logger.h"
#include "../util-misc/cross.h"
#include "../util-data/fine-malloc.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _MSC_VER
#pragma warning(disable:4204)
#endif

#define BUCKET_COUNT 16

#define REGRESS(x) if (!(x)) return (LOG(LEVEL_ERROR, "regression failed %s:%d\n", __FILE__, __LINE__)|1)

/* An invalid range, where begin comes after the end */
static struct Range INVALID_RANGE = {2,1};

/***************************************************************************
 * Does a linear search to see if the list contains the address/port.
 * FIXME: This should be upgraded to a binary search. However, we don't
 * really use it in any performance critical code, so it's okay
 * as a linear search.
 ***************************************************************************/
bool
rangelist_is_contains(const struct RangeList *targets, unsigned addr)
{
    unsigned i;
    for (i=0; i<targets->count; i++) {
        struct Range *range = &targets->list[i];

        if (range->begin <= addr && addr <= range->end)
            return true;
    }
    return false;
}

/***************************************************************************
 * Returns the first CIDR range (which can be specified with prefix bits)
 * that fits within the input range. For example, consider the range
 * [10.0.0.4->10.0.0.255]. This does't match the bigger CIDR range.
 * The first range that would fit would be [10.0.0.04/30], or
 * [10.0.0.4->10.0.0.7].
 *
 * Using this function allows us to decompose
 ***************************************************************************/
struct Range
range_first_cidr(const struct Range range, unsigned *prefix_bits) {
    struct Range result = {range.begin, range.end};
    unsigned zbits = 0;

    /* Kludge: Special Case:
     * All inputs work but the boundary case of [0.0.0.0/0] or
     * [0.0.0.0-255.255.255.255]. I can't be bothered to figure out
     * why the algorithm doesn't work with this range, so I'm just
     * going to special case it here*/
    if (range.begin == 0 && range.end == 0xFFFFffff) {
        if (prefix_bits != NULL)
            *prefix_bits = 0;
        return range;
    }

    /* Count the number of trailing/suffix zeros, which may be range
     * from none (0) to 32 (all bits are 0) */
    for (zbits = 0; zbits <= 32; zbits++) {
        if ((range.begin & (1<<zbits)) != 0)
            break;
    }

    /* Now search for the largest CIDR range that starts with this
     * begining address that fits within the ending address*/
    while (zbits > 0) {
        unsigned mask = ~(0xFFFFFFFF << zbits);

        if (range.begin + mask > range.end)
            zbits--;
        else
            break;
    }

    result.begin = range.begin;
    result.end = range.begin + ~(0xFFFFffff << zbits);
    if (prefix_bits != NULL)
        *prefix_bits = 32-zbits;

    return result;
}

bool
range_is_cidr(const struct Range range, unsigned *prefix_bits) {
    struct Range out = range_first_cidr(range, prefix_bits);
    if (out.begin == range.begin && out.end == range.end)
        return true;
    else {
        if (prefix_bits != NULL)
            *prefix_bits = 0xFFFFFFFF;
        return false;
    }
}

/***************************************************************************
 * Test if two ranges overlap.
 * FIXME: I need to change this so that it (a) doesn't trigger on invalid
 * ranges (those where begin>end) and (b) use a simpler algorithm
 ***************************************************************************/
static int
range_is_overlap(struct Range lhs, struct Range rhs)
{
    if (lhs.begin < rhs.begin) {
        if (lhs.end == 0xFFFFFFFF || lhs.end + 1 >= rhs.begin)
            return 1;
    }
    if (lhs.begin >= rhs.begin) {
        if (lhs.end <= rhs.end)
            return 1;
    }

    if (rhs.begin < lhs.begin) {
        if (rhs.end == 0xFFFFFFFF || rhs.end + 1 >= lhs.begin)
            return 1;
    }
    if (rhs.begin >= lhs.begin) {
        if (rhs.end <= lhs.end)
            return 1;
    }

    return 0;
}


/***************************************************************************
 * Combine two ranges, such as when they overlap.
 ***************************************************************************/
static void
range_combine(struct Range *lhs, struct Range rhs)
{
    if (lhs->begin > rhs.begin)
        lhs->begin = rhs.begin;
    if (lhs->end < rhs.end)
        lhs->end = rhs.end;
}

/***************************************************************************
 * Callback for qsort() for comparing two ranges
 ***************************************************************************/
static int
range_compare(const void *lhs, const void *rhs)
{
    struct Range *left = (struct Range *)lhs;
    struct Range *right = (struct Range *)rhs;

    if (left->begin < right->begin)
        return -1;
    else if (left->begin > right->begin)
        return 1;
    else
        return 0;
}


/***************************************************************************
 ***************************************************************************/
void
rangelist_sort(struct RangeList *targets)
{
    size_t i;
    struct RangeList newlist = {0};
    unsigned original_count = targets->count;

    /* Empty lists are, of course, sorted. We need to set this
     * to avoid an error later on in the code which asserts that
     * the lists are sorted */
    if (targets->count == 0) {
        targets->is_sorted = 1;
        return;
    }
    
    /* If it's already sorted, then skip this */
    if (targets->is_sorted) {
        return;
    }
    
    
    /* First, sort the list */
    LOG(LEVEL_DEBUG, "[+] range:sort: sorting...\n");
    qsort(  targets->list,              /* the array to sort */
            targets->count,             /* number of elements to sort */
            sizeof(targets->list[0]),   /* size of element */
            range_compare);
    
    
    /* Second, combine all overlapping ranges. We do this by simply creating
     * a new list from a sorted list, so we don't have to remove things in the
     * middle when collapsing overlapping entries together, which is painfully
     * slow. */
    LOG(LEVEL_DEBUG, "[+] range:sort: combining...\n");
    for (i=0; i<targets->count; i++) {
        rangelist_add_range(&newlist, targets->list[i].begin, targets->list[i].end);
    }
    
    LOG(LEVEL_DEBUG, "[+] range:sort: combined from %u elements to %u elements\n", original_count, newlist.count);
    free(targets->list);
    targets->list = newlist.list;
    targets->count = newlist.count;
    newlist.list = 0;

    LOG(LEVEL_INFO, "[+] range:sort: done...\n");

    targets->is_sorted = 1;
}

/***************************************************************************
 * Add the IPv4 range to our list of ranges.
 ***************************************************************************/
void
rangelist_add_range(struct RangeList *targets, unsigned begin, unsigned end)
{
    struct Range range;

    range.begin = begin;
    range.end = end;

    /* auto-expand the list if necessary */
    if (targets->count + 1 >= targets->max) {
        targets->max = targets->max * 2 + 1;
        targets->list = REALLOCARRAY(targets->list, targets->max, sizeof(targets->list[0]));
    }

    /* If empty list, then add this one */
    if (targets->count == 0) {
        targets->list[0] = range;
        targets->count++;
        targets->is_sorted = 1;
        return;
    }

    /* If new range overlaps the last range in the list, then combine it
     * rather than appending it. This is an optimization for the fact that
     * we often read in sequential addresses */
    if (range_is_overlap(targets->list[targets->count - 1], range)) {
        range_combine(&targets->list[targets->count - 1], range);
        targets->is_sorted = 0;
        return;
    }

    /* append to the end of our list */
    targets->list[targets->count] = range;
    targets->count++;
    targets->is_sorted = 0;
}

/** Use this when adding TCP ports, to avoid the comoplication of how
 * ports are stored */
void
rangelist_add_range_tcp(struct RangeList *targets, unsigned begin, unsigned end) {
    rangelist_add_range(targets,
                            Templ_TCP + begin,
                            Templ_TCP + end);
}

/** Use this when adding UDP ports, to avoid the comoplication of how
 * ports are stored */
void
rangelist_add_range_udp(struct RangeList *targets, unsigned begin, unsigned end) {
    rangelist_add_range(targets,
                            Templ_UDP + begin,
                            Templ_UDP + end);
}


/***************************************************************************
 * This is the "free" function for the list, freeing up any memory we've
 * allocated.
 ***************************************************************************/
void
rangelist_remove_all(struct RangeList *targets)
{
    free(targets->list);
    free(targets->picker);
    memset(targets, 0, sizeof(*targets));
}

/***************************************************************************
 ***************************************************************************/
void
rangelist_merge(struct RangeList *list1, const struct RangeList *list2)
{
    unsigned i;
    
    for (i=0; i<list2->count; i++) {
        rangelist_add_range(list1, list2->list[i].begin, list2->list[i].end);
    }
    rangelist_sort(list1);
}


/***************************************************************************
 * Parse an IPv4 address from a line of text, moving the offset forward
 * to the first non-IPv4 character
 ***************************************************************************/
static int
parse_ipv4(const char *line, unsigned *inout_offset, unsigned max, unsigned *ipv4)
{
    unsigned offset = *inout_offset;
    unsigned result = 0;
    unsigned i;

    for (i=0; i<4; i++) {
        unsigned x = 0;
        unsigned digits = 0;

        if (offset >= max)
            return -4;
        if (!isdigit(line[offset]&0xFF))
            return -1;

        /* clear leading zeros */
        while (offset < max && line[offset] == '0')
            offset++;

        /* parse maximum of 3 digits */
        while (offset < max && isdigit(line[offset]&0xFF)) {
            x = x * 10 + (line[offset] - '0');
            offset++;
            if (++digits > 3)
                return -2;
        }
        if (x > 255)
            return -5;
        result = result * 256 + (x & 0xFF);
        if (i == 3)
            break;

        if (line[offset] != '.')
            return -3;
        offset++; /* skip dot */
    }

    *inout_offset = offset;
    *ipv4 = result;

    return 0; /* parse OK */
}


/****************************************************************************
 * Parse from text an IPv4 address range. This can be in one of several
 * formats:
 * - '192.168.1.1" - a single address
 * - '192.168.1.0/24" - a CIDR spec
 * - '192.168.1.0-192.168.1.255' - a range
 * @param line
 *      Part of a line of text, probably read from a commandline or conf
 *      file.
 * @param inout_offset
 *      On input, the offset from the start of the line where the address
 *      starts. On output, the offset of the first character after the
 *      range, or equal to 'max' if the line prematurely ended.
 * @param max
 *      The maximum length of the line.
 * @return
 *      The first and last address of the range, inclusive.
 ****************************************************************************/
struct Range
range_parse_ipv4(const char *line, unsigned *inout_offset, unsigned max)
{
    unsigned offset;
    struct Range result;
    static const struct Range badrange = {0xFFFFFFFF, 0};
    int err;

    if (line == NULL)
        return badrange;

    if (inout_offset == NULL) {
         inout_offset = &offset;
         offset = 0;
         max = (unsigned)strlen(line);
    } else
        offset = *inout_offset;


    /* trim whitespace */
    while (offset < max && isspace(line[offset]&0xFF))
        offset++;

    /* get the first IP address */
    err = parse_ipv4(line, &offset, max, &result.begin);
    if (err) {
        return badrange;
    }
    result.end = result.begin;

    /* trim whitespace */
    while (offset < max && isspace(line[offset]&0xFF))
        offset++;

    /* If only one IP address, return that */
    if (offset >= max)
        goto end;

    /*
     * Handle CIDR address of the form "10.0.0.0/8"
     */
    if (line[offset] == '/') {
        uint64_t prefix = 0;
        uint64_t mask = 0;
        unsigned digits = 0;

        /* skip slash */
        offset++;

        if (!isdigit(line[offset]&0xFF)) {
            return badrange;
        }

        /* strip leading zeroes */
        while (offset<max && line[offset] == '0')
            offset++;

        /* parse decimal integer */
        while (offset<max && isdigit(line[offset]&0xFF)) {
            prefix = prefix * 10 + (line[offset++] - '0');
            if (++digits > 2)
                return badrange;
        }
        if (prefix > 32)
            return badrange;

        /* Create the mask from the prefix */
        mask = 0xFFFFFFFF00000000ULL >> prefix;

        /* Mask off any non-zero bits from the start
         * TODO print warning */
        result.begin &= mask;

        /* Set all suffix bits to 1, so that 192.168.1.0/24 has
         * an ending address of 192.168.1.255. */
        result.end = result.begin | (unsigned)~mask;
        goto end;
    }

    /*
     * Handle a dashed range like "10.0.0.100-10.0.0.200"
     */
    if (offset<max && line[offset] == '-') {
        unsigned ip;

        offset++;
        err = parse_ipv4(line, &offset, max, &ip);
        if (err)
            return badrange;
        if (ip < result.begin) {
            result.begin = 0xFFFFFFFF;
            result.end = 0x00000000;
            LOG(LEVEL_ERROR, "err: ending addr %u.%u.%u.%u cannot come before starting addr %u.%u.%u.%u\n",
                ((ip>>24)&0xFF), ((ip>>16)&0xFF), ((ip>>8)&0xFF), ((ip>>0)&0xFF),
                ((result.begin>>24)&0xFF), ((result.begin>>16)&0xFF), ((result.begin>>8)&0xFF), ((result.begin>>0)&0xFF)
                );
        } else
            result.end = ip;
        goto end;
    }

end:
    *inout_offset = offset;
    return result;
}


/**
 * Applies the (presumably overlapping) exclude range to the target. This can have
 * four outcomes:
 *  - there is no overlap, in which case 'target' is unchanged, and 'split'
 *    is set to INVALID.
 *  - the entire target is excluded, in which case it's set to INVALID.
 *  - the overlap is at the beginning, in which case the 'begin' is increased.
 *  - the overlap is at the end, in which case 'end' is reduced.
 *  - the overlap is in the middle, in which case the target is split
 *    in two, with 'target' becoming the low addresses, and 'split' becoming
 *    the high addresses.
 */
static void
range_apply_exclude(const struct Range exclude, struct Range *target, struct Range *split)
{
    /* Set 'split' to invalid to start with */
    split->begin = 2;
    split->end = 1;

    /* Case 1: no overlap */
    if (target->begin > exclude.end || target->end < exclude.begin) {
        return;
    }
    
    /* Case 2: complete overlap, mark target as invalid and return */
    if (target->begin >= exclude.begin && target->end <= exclude.end) {
        target->begin = 2;
        target->end = 1;
        return;
    }
    
    /* Case 3: overlap at start */
    if (target->begin >= exclude.begin && target->end > exclude.end) {
        target->begin = exclude.end + 1;
        return;
    }
    
    /* Case 4: overlap at end */
    if (target->begin < exclude.begin && target->end <= exclude.end) {
        target->end = exclude.begin - 1;
        return;
    }
    
    /* Case 5: this range needs to be split */
    if (target->begin < exclude.begin && target->end > exclude.end) {
        split->end = target->end;
        split->begin = exclude.end + 1;
        target->end = exclude.begin - 1;
        return;
    }
    
    /* No other condition should be possible */
    assert(!"possible");
}

/***************************************************************************
 ***************************************************************************/
bool
range_is_valid(struct Range range)
{
    return range.begin <= range.end;
}

/***************************************************************************
 * Apply the exclude ranges, which means removing everything from "targets"
 * that's also in "exclude". This can make the target list even bigger
 * as individually excluded address chop up large ranges.
 ***************************************************************************/
void
rangelist_exclude(  struct RangeList *targets,
                  struct RangeList *excludes)
{
    unsigned i;
    unsigned x;
    struct RangeList newlist = {0};
    
    /* Both lists must be sorted */
    rangelist_sort(targets);
    rangelist_sort(excludes);
    
    /* Go through all target ranges, apply excludes to them
     * (which may split into two ranges), and add them to
     * the new target list */
    x = 0;
    for (i=0; i<targets->count; i++) {
        struct Range range = targets->list[i];
        
        /* Move the exclude forward until we find a potentially
         * overlapping candidate */
        while (x < excludes->count && excludes->list[x].end < range.begin)
            x++;
        
        /* Keep applying excludes to this range as long as there are overlaps */
        while (x < excludes->count && excludes->list[x].begin <= range.end) {
            struct Range split = INVALID_RANGE;
            
            range_apply_exclude(excludes->list[x], &range, &split);
            
            /* If there is a split, then add the original range to our list
             * and then set that range to the split-ed portion */
            if (range_is_valid(split)) {
                rangelist_add_range(&newlist, range.begin, range.end);
                memcpy(&range, &split, sizeof(range));
            }
            
            if (excludes->list[x].begin > range.end)
                break;
            
            x++;
        }
        
        /* If the range hasn't been completely excluded, then add the remnants */
        if (range_is_valid(range)) {
            rangelist_add_range(&newlist, range.begin, range.end);
        }
    }

    /* Now free the old list and move over the new list */
    free(targets->list);
    targets->list = newlist.list;
    targets->count = newlist.count;
    newlist.list = NULL;
    newlist.count = 0;
    
    /* Since chopping up large ranges can split ranges, this can
     * grow the list so we need to re-sort it */
    rangelist_sort(targets);
}


/***************************************************************************
 * Counts the total number of addresses in all the ranges combined.
 * For 0.0.0.0/0, this will be 0x100000000, which means we have to use a
 * larger number than 32-bit to return the result. This assumes that
 * all overlaps have been resolved in the list (i.e. it's been sorted).
 ***************************************************************************/
uint64_t
rangelist_count(const struct RangeList *targets)
{
    unsigned i;
    uint64_t result = 0;

    for (i=0; i<targets->count; i++) {
        result += (uint64_t)targets->list[i].end - (uint64_t)targets->list[i].begin + 1UL;
    }

    return result;
}


/***************************************************************************
 * Get's the indexed port/address.
 *
 * Note that this requires a search of all the ranges. Currently, this is
 * done by a learn search of the ranges. This needs to change, because
 * once we start adding in a lot of "exclude ranges", the address space
 * will get fragmented, and the linear search will take too long.
 ***************************************************************************/
static unsigned
rangelist_pick_linearsearch(const struct RangeList *targets, uint64_t index)
{
    unsigned i;

    for (i=0; i<targets->count; i++) {
        uint64_t range = (uint64_t)targets->list[i].end - (uint64_t)targets->list[i].begin + 1UL;
        if (index < range)
            return (unsigned)(targets->list[i].begin + index);
        else
            index -= range;
    }

    assert(!"end of list");
    return 0;
}

/***************************************************************************
 ***************************************************************************/
unsigned
rangelist_pick(const struct RangeList *targets, uint64_t index)
{
    unsigned maxmax = targets->count;
    unsigned min = 0;
    unsigned max = targets->count;
    unsigned mid;
    const unsigned *picker = targets->picker;

    if (!targets->is_sorted)
        rangelist_sort((struct RangeList *)targets);
    assert(targets->is_sorted);

    if (picker == NULL) {
        /* optimization wasn't done */
        return rangelist_pick_linearsearch(targets, index);
    }


    for (;;) {
        mid = min + (max-min)/2;
        if (index < picker[mid]) {
            max = mid;
            continue;
        } if (index >= picker[mid]) {
            if (mid + 1 == maxmax)
                break;
            else if (index < picker[mid+1])
                break;
            else
                min = mid+1;
        }
    }

    return (unsigned)(targets->list[mid].begin + (index - picker[mid]));
}


/***************************************************************************
 * The normal "pick" function is a linear search, which is slow when there
 * are a lot of ranges. Therefore, the "pick2" creates sort of binary
 * search that'll be a lot faster. We choose "binary search" because
 * it's the most cache-efficient, having the least overhead to fit within
 * the cache.
 ***************************************************************************/
void
rangelist_optimize(struct RangeList *targets)
{
    unsigned *picker;
    unsigned i;
    unsigned total = 0;

    if (targets->count == 0)
        return;

    /* This technique only works when the targets are in
     * ascending order */
    if (!targets->is_sorted)
        rangelist_sort(targets);

    if (targets->picker)
        free(targets->picker);

    picker = REALLOCARRAY(NULL, targets->count, sizeof(*picker));

    for (i=0; i<targets->count; i++) {
        picker[i] = total;
        total += targets->list[i].end - targets->list[i].begin + 1;
    }

    targets->picker = picker;
}


/***************************************************************************
 * This returns a character pointer where parsing ends so that it can
 * handle multiple stuff on the same line
 ***************************************************************************/
const char *
rangelist_parse_ports(struct RangeList *ports, const char *string, unsigned *is_error, unsigned proto_offset)
{
    char *p = (char*)string;
    unsigned tmp = 0;

    if (is_error == NULL)
        is_error = &tmp;
    
    *is_error = 0;
    while (*p) {
        unsigned port;
        unsigned end;

        /* skip whitespace */
        while (*p && isspace(*p & 0xFF))
            p++;

        /* end at comment */
        if (*p == 0 || *p == '#')
            break;

        /* special processing. Nmap allows ports to be prefixed with a
         * characters to clarify TCP, UDP, or SCTP */
        if (isalpha(*p&0xFF) && p[1] == ':') {
            switch (*p) {
                case 'T': case 't':
                    proto_offset = 0;
                    break;
                case 'U': case 'u':
                    proto_offset = Templ_UDP;
                    break;
                case 'S': case 's':
                    proto_offset = Templ_SCTP;
                    break;
                case 'O': case 'o':
                    proto_offset = Templ_Oproto_first;
                    break;
                case 'I': case 'i':
                    proto_offset = Templ_ICMP_echo;
                    break;
                default:
                    LOG(LEVEL_ERROR, "bad port character = %c\n", p[0]);
                    *is_error = 1;
                    return p;
            }
            p += 2;
        }

        /*
         * Get the start of the range.
         */
        if (p[0] == '-') {
            /* nmap style port range spec meaning starting with 0 */
            port = 1;
        } else if (isdigit(p[0] & 0xFF)) {
            port = (unsigned)strtoul(p, &p, 0);
        } else {
            break;
        }

        /* 
         * Get the end of the range 
         */
        if (*p == '-') {
            p++;
            if (!isdigit(*p)) {
                /* nmap style range spec meaning end with 65535 */
                end = (proto_offset == Templ_Oproto_first) ? 0xFF : 0xFFFF;
            } else {
                end = (unsigned)strtoul(p, &p, 0);
            }
        } else
            end = port;

        /* Check for out-of-range */
        if (port > 0xFF && proto_offset == Templ_Oproto_first) {
            *is_error = 2;
            return p;
        } else if (port > 0xFFFF || end > 0xFFFF || end < port) {
            *is_error = 2;
            return p;
        }

        /* Add to our list */
        rangelist_add_range(ports, port+proto_offset, end+proto_offset);

        /* skip trailing whitespace */
        while (*p && isspace(*p & 0xFF))
            p++;

        /* Now get the next port/range if there is one */
        if (*p != ',')
            break;
        p++;
    }

    return p;
}

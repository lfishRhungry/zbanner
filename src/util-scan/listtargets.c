#include "listtargets.h"
#include <assert.h>
#include "../util-out/logger.h"
#include "../crypto/crypto-blackrock.h"

void list_ip_port(XConf *xconf) {
    uint64_t  i;
    uint64_t  range;
    uint64_t  start;
    uint64_t  end;
    BlackRock blackrock;
    unsigned  increment    = xconf->shard.of;
    uint64_t  dynamic_seed = xconf->seed;

    /* If called with no ports, then create a pseudo-port needed
     * for the internal algorithm. */
    if (!targetset_has_any_ports(&xconf->targets)) {
        targetset_add_port_string(&xconf->targets, "o:0", 0);
        // LOG(LEVEL_WARN, "no ports were specified or remained, a fake port o:0
        // was" " specified automaticlly.\n");
    }
    targetset_optimize(&xconf->targets);

    /**
     * The "range" is the total number of IP/port combinations that
     * the scan can produce */
    range = targetset_count(&xconf->targets).lo;

infinite:
    blackrock1_init(&blackrock, range, dynamic_seed, 14);

    start = xconf->resume.index + (xconf->shard.one - 1);
    end   = range;

    for (i = start; i < end;) {
        uint64_t  xXx;
        unsigned  port;
        unsigned  ip_proto;
        ipaddress addr;

        xXx = blackrock1_shuffle(&blackrock, i);

        targetset_pick(&xconf->targets, xXx, &addr, &port);

        ip_proto = get_actual_proto_port(&port);

        if (xconf->targets.count_ports == 1) {
            ipaddress_formatted_t fmt = ipaddress_fmt(addr);
            /* This is the normal case */
            printf("%s\n", fmt.string);
        } else {
            ipaddress_formatted_t fmt = ipaddress_fmt(addr);
            if (addr.version == 6)
                printf("%s ", fmt.string);
            else
                printf("%s ", fmt.string);

            switch (ip_proto) {
                case IP_PROTO_TCP:
                    printf("%u", port);
                    break;
                case IP_PROTO_UDP:
                    printf("u:%u", port);
                    break;
                case IP_PROTO_SCTP:
                    printf("s:%u", port);
                    break;
                default:
                    printf("o:%u", port);
                    break;
            }

            printf("\n");
        }

        i += increment; /* <------ increment by 1 normally, more with
                           shards/NICs */
    }

    if (xconf->is_infinite) {
        if (!xconf->is_static_seed) {
            dynamic_seed++;
        }
        goto infinite;
    }
}

/***************************************************************************
 ***************************************************************************/
static unsigned count_cidr6_bits(struct Range6 range) {
    uint64_t i;

    /* Kludge: can't handle more than 64-bits of CIDR ranges */
    if (range.begin.hi != range.begin.lo)
        return 0;

    for (i = 0; i < 64; i++) {
        uint64_t mask = 0xFFFFFFFFffffffffull >> i;

        if ((range.begin.lo & ~mask) == (range.end.lo & ~mask)) {
            if ((range.begin.lo & mask) == 0 && (range.end.lo & mask) == mask)
                return (unsigned)i;
        }
    }

    return 0;
}

/***************************************************************************
 ***************************************************************************/
void list_range(XConf *xconf) {
    struct RangeList  *list4 = &xconf->targets.ipv4;
    struct Range6List *list6 = &xconf->targets.ipv6;
    unsigned           i;
    FILE              *fp = stdout;

    for (i = 0; i < list4->list_len; i++) {
        unsigned     prefix_length;
        struct Range range = list4->list[i];

        if (range.begin == range.end) {
            fprintf(fp, "%u.%u.%u.%u\n", (range.begin >> 24) & 0xFF,
                    (range.begin >> 16) & 0xFF, (range.begin >> 8) & 0xFF,
                    (range.begin >> 0) & 0xFF);
        } else if (range_is_cidr(range, &prefix_length)) {
            fprintf(fp, "%u.%u.%u.%u/%u\n", (range.begin >> 24) & 0xFF,
                    (range.begin >> 16) & 0xFF, (range.begin >> 8) & 0xFF,
                    (range.begin >> 0) & 0xFF, prefix_length);
        } else {
            fprintf(fp, "%u.%u.%u.%u-%u.%u.%u.%u\n", (range.begin >> 24) & 0xFF,
                    (range.begin >> 16) & 0xFF, (range.begin >> 8) & 0xFF,
                    (range.begin >> 0) & 0xFF, (range.end >> 24) & 0xFF,
                    (range.end >> 16) & 0xFF, (range.end >> 8) & 0xFF,
                    (range.end >> 0) & 0xFF);
        }
    }

    for (i = 0; i < list6->list_len; i++) {
        struct Range6         range = list6->list[i];
        ipaddress_formatted_t fmt   = ipv6address_fmt(range.begin);
        fprintf(fp, "%s", fmt.string);
        if (!ipv6address_is_equal(range.begin, range.end)) {
            unsigned cidr_bits = count_cidr6_bits(range);
            if (cidr_bits) {
                fprintf(fp, "/%u", cidr_bits);
            } else {
                fmt = ipv6address_fmt(range.end);
                fprintf(fp, "-%s", fmt.string);
            }
        }
        fprintf(fp, "\n");
    }
}
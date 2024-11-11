#include "list-targets.h"
#include <assert.h>
#include "../util-out/logger.h"
#include "../crypto/crypto-blackrock.h"
#include "../as/as-query.h"

void list_ip_port(XConf *xconf) {
    uint64_t         i;
    uint64_t         range;
    uint64_t         start;
    uint64_t         end;
    BlackRock        blackrock;
    struct AS_Query *as_query;
    unsigned         increment    = xconf->shard.of;
    uint64_t         dynamic_seed = xconf->seed;
    bool             in_order     = xconf->listtargets_in_order;

    if (xconf->out_conf.output_as_info && !xconf->as_query) {
        LOG(LEVEL_ERROR, "cannot output AS info to listed targets because no "
                         "ip2asn files are specified.\n");
        LOG(LEVEL_HINT,
            "load AS info by specifying --ip2asn-v4 or/and --ip2asn-v6.\n");
        return;
    }

    /* If called with no ports, then create a pseudo-port needed
     * for the internal algorithm. */
    if (!targetset_has_any_ports(&xconf->targets)) {
        targetset_add_port_string(&xconf->targets, "o:0", 0);
        targetset_optimize(&xconf->targets);
    }

    /**
     * !only support 63-bit scans
     */
    if (int128_bitcount(targetset_count(&xconf->targets)) > 63) {
        LOG(LEVEL_ERROR, "range too large for target listing: %u-bits\n",
            int128_bitcount(targetset_count(&xconf->targets)));
        LOG(LEVEL_HINT, "target_count = ip_count * port_count\n");
        LOG(LEVEL_HINT, "max targets count is within 63-bits\n");
        return;
    }

    /**
     * The "range" is the total number of IP/port combinations that
     * the scan can produce */
    range = targetset_count(&xconf->targets).lo;

    /**
     * load as info
     */
    as_query = xconf->as_query;

infinite:
    if (!in_order)
        blackrock1_init(&blackrock, range, dynamic_seed, 14);

    start = xconf->resume.index + (xconf->shard.one - 1);
    end   = range;

    for (i = start; i < end;) {
        uint64_t  xXx = i;
        unsigned  port;
        unsigned  ip_proto;
        ipaddress addr;

        if (!in_order)
            xXx = blackrock1_shuffle(&blackrock, i);

        targetset_pick(&xconf->targets, xXx, &addr, &port);

        ip_proto = get_actual_proto_port(&port);

        ipaddress_formatted_t fmt = ipaddress_fmt(addr);
        printf("%s", fmt.string);

        if (xconf->targets.count_ports != 1) {
            switch (ip_proto) {
                case IP_PROTO_TCP:
                    printf(" %u", port);
                    break;
                case IP_PROTO_UDP:
                    printf(" u:%u", port);
                    break;
                case IP_PROTO_SCTP:
                    printf(" s:%u", port);
                    break;
                default:
                    printf(" o:%u", port);
                    break;
            }
        }

        if (xconf->out_conf.output_as_info) {
            struct AS_Info as_info = as_query_search_ip(as_query, addr);
            printf(", AS%u, %s, %s", as_info.asn, as_info.country_code,
                   as_info.desc);
        }

        printf("\n");

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
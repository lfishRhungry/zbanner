#include "list-targets.h"
#include <assert.h>
#include "../util-out/logger.h"
#include "../crypto/crypto-blackrock.h"
#include "../as/as-query.h"

void listtargets_ip_port(XConf *xconf, FILE *fp) {
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

    /**
     * NOTE: Must has at least one ip and one port.
     */
    if (xconf->targets.count_ipv4s == 0 && xconf->targets.count_ipv6s.hi == 0 &&
        xconf->targets.count_ipv6s.lo == 0) {
        LOG(LEVEL_ERROR, "target IP address list empty.\n");
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
        LOG(LEVEL_ERROR, "range is too large for listing: %u-bits\n",
            int128_bitcount(targetset_count(&xconf->targets)));
        LOG(LEVEL_HINT, "range = target_count * endpoint_count\n");
        LOG(LEVEL_HINT, "max range is within 63-bits.\n");
        LOG(LEVEL_HINT, "may try to list them in range format or CIDR.\n");
        return;
    }

    LOG(LEVEL_HINT, "Listing %" PRIu64 " targets",
        xconf->targets.count_ipv4s + xconf->targets.count_ipv6s.lo);
    if (xconf->targets.count_ports > 1) {
        LOG(LEVEL_OUT, " [%" PRIu64 " endpoints each]",
            xconf->targets.count_ports);
    }
    if (xconf->shard.of > 1) {
        LOG(LEVEL_OUT, " in shard %u/%u", xconf->shard.one, xconf->shard.of);
    }
    LOG(LEVEL_OUT, ".\n");

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
        fprintf(fp, "%s", fmt.string);

        if (xconf->targets.count_ports != 1) {
            switch (ip_proto) {
                case IP_PROTO_TCP:
                    fprintf(fp, " %u", port);
                    break;
                case IP_PROTO_UDP:
                    fprintf(fp, " u:%u", port);
                    break;
                case IP_PROTO_SCTP:
                    fprintf(fp, " s:%u", port);
                    break;
                default:
                    fprintf(fp, " o:%u", port);
                    break;
            }
        }

        if (xconf->out_conf.output_as_info) {
            struct AS_Info as_info = as_query_search_ip(as_query, addr);
            fprintf(fp, ", AS%u, %s, %s", as_info.asn, as_info.country_code,
                    as_info.desc);
        }

        fprintf(fp, "\n");

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
void listtargets_range(XConf *xconf, FILE *fp) {
    struct RangeList  *list4 = &xconf->targets.ipv4;
    struct Range6List *list6 = &xconf->targets.ipv6;
    unsigned           i;

    LOG(LEVEL_HINT, "listing %u IPv4 ranges and %u IPv6 ranges.\n",
        xconf->targets.ipv4.list_len, xconf->targets.ipv6.list_len);

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
        bool                  exact = false;
        struct Range6         range = list6->list[i];
        ipaddress_formatted_t fmt   = ipv6address_fmt(range.begin);

        fprintf(fp, "%s", fmt.string);
        if (!ipv6address_is_equal(range.begin, range.end)) {
            unsigned cidr_bits = range6list_cidr_bits(&range, &exact);

            if (exact && cidr_bits) {
                fprintf(fp, "/%u", cidr_bits);
            } else {
                fmt = ipv6address_fmt(range.end);
                fprintf(fp, "-%s", fmt.string);
            }
        }
        fprintf(fp, "\n");
    }
}

/***************************************************************************
 ***************************************************************************/
void listtargets_cidr(XConf *xconf, FILE *fp) {
    unsigned i;

    LOG(LEVEL_HINT, "listing %u IPv4 ranges and %u IPv6 ranges in CIDR.\n",
        xconf->targets.ipv4.list_len, xconf->targets.ipv6.list_len);

    /*
     * For all IPv4 ranges ...
     */
    for (i = 0; i < xconf->targets.ipv4.list_len; i++) {
        /* Get the next range in the list */
        struct Range range = xconf->targets.ipv4.list[i];

        /* If not a single CIDR range, print all the CIDR ranges
         * needed to completely represent this addres */
        for (;;) {
            unsigned     prefix_length;
            struct Range cidr;

            /* Find the largest CIDR range (one that can be specified
             * with a /prefix) at the start of this range. */
            cidr = range_first_cidr(range, &prefix_length);
            fprintf(fp, "%u.%u.%u.%u/%u\n", (cidr.begin >> 24) & 0xFF,
                    (cidr.begin >> 16) & 0xFF, (cidr.begin >> 8) & 0xFF,
                    (cidr.begin >> 0) & 0xFF, prefix_length);

            /* If this is the last range, then stop. There are multiple
             * ways to gets to see if we get to the end, but I think
             * this is the best. */
            if (cidr.end >= range.end)
                break;

            /* If the CIDR range didn't cover the entire range,
             * then remove it from the beginning of the range
             * and process the remainder */
            range.begin = cidr.end + 1;
        }
    }

    /*
     * For all IPv6 ranges...
     */
    for (i = 0; i < xconf->targets.ipv6.list_len; i++) {
        struct Range6 range = xconf->targets.ipv6.list[i];
        bool          exact = false;
        while (!exact) {
            ipaddress_formatted_t fmt = ipv6address_fmt(range.begin);
            fprintf(fp, "%s", fmt.string);
            if (range.begin.hi == range.end.hi &&
                range.begin.lo == range.end.lo) {
                fprintf(fp, "/128");
                exact = true;
            } else {
                unsigned cidr_bits = range6list_cidr_bits(&range, &exact);
                fprintf(fp, "/%u", cidr_bits);
            }
            fprintf(fp, "\n");
        }
    }
}
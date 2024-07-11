#include "listtargets.h"
#include "../util-out/logger.h"
#include "../crypto/crypto-blackrock.h"


void
listip(XConf *xconf)
{
    uint64_t  i;
    uint64_t  range;
    uint64_t  start;
    uint64_t  end;
    BlackRock blackrock;
    unsigned  increment    = xconf->shard.of;
    uint64_t  dynamic_seed = xconf->seed;

    /* If called with no ports, then create a pseudo-port needed
     * for the internal algorithm. */
    if (!targetip_has_target_ports(&xconf->targets)) {
        targetip_add_port_string(&xconf->targets, "o:0", 0);
        // LOG(LEVEL_WARN, "no ports were specified or remained, a fake port o:0 was"
        // " specified automaticlly.\n");
    }
    targetip_optimize(&xconf->targets);

    /**
     * The "range" is the total number of IP/port combinations that
     * the scan can produce */
    range = targetip_range(&xconf->targets).lo;


infinite:
    blackrock1_init(&blackrock, range, dynamic_seed, 14);

    start = xconf->resume.index + (xconf->shard.one-1);
    end   = range;

    for (i=start; i<end; ) {
        uint64_t xXx;
        unsigned port;
        unsigned ip_proto;
        ipaddress addr;

        xXx = blackrock1_shuffle(&blackrock, i);

        targetip_pick(&xconf->targets, xXx, &addr, &port);

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

        i += increment; /* <------ increment by 1 normally, more with shards/NICs */
    }

    if (xconf->is_infinite) {
        if (!xconf->is_static_seed) {
            dynamic_seed++;
        }
        goto infinite;
    }
}

#include "listscan.h"
#include "logger.h"
#include "../crypto/crypto-blackrock.h"


void
listscan(struct Xconf *xconf)
{
    uint64_t i;
    uint64_t range;
    uint64_t start;
    uint64_t end;
    struct BlackRock blackrock;
    unsigned increment = xconf->shard.of;
    uint64_t seed = xconf->seed;

    /* If called with no ports, then create a pseudo-port needed
     * for the internal algorithm. */
    if (!massip_has_target_ports(&xconf->targets))
        rangelist_add_range(&xconf->targets.ports, 80, 80);
    massip_optimize(&xconf->targets);

    /* The "range" is the total number of IP/port combinations that
     * the scan can produce */
    range = massip_range(&xconf->targets).lo;


infinite:
    blackrock_init(&blackrock, range, seed, xconf->blackrock_rounds);

    start = xconf->resume.index + (xconf->shard.one-1);
    end = range;
    if (xconf->resume.count && end > start + xconf->resume.count)
        end = start + xconf->resume.count;
    end += (uint64_t)(xconf->retries * xconf->max_rate);

    for (i=start; i<end; ) {
        uint64_t xXx;
        unsigned port;
        ipaddress addr;

        xXx = blackrock_shuffle(&blackrock,  i);

        massip_pick(&xconf->targets, xXx, &addr, &port);
        

        if (xconf->targets.count_ports == 1) {
            ipaddress_formatted_t fmt = ipaddress_fmt(addr);
            /* This is the normal case */
            printf("%s\n", fmt.string);
        } else {
            ipaddress_formatted_t fmt = ipaddress_fmt(addr);
            if (addr.version == 6)
                printf("[%s]:%u\n", fmt.string, port);
            else
                printf("%s:%u\n", fmt.string, port);
        }

        i += increment; /* <------ increment by 1 normally, more with shards/NICs */
    }

    if (xconf->is_infinite) {
        seed++;
        goto infinite;
    }
}

#include <string.h>

#include "templ-pkt.h"
#include "../util-data/fine-malloc.h"


/***************************************************************************
 ***************************************************************************/
TmplSet templ_copy(const TmplSet *templset)
{
    TmplSet result;
    unsigned i;

    memcpy(&result, templset, sizeof(result));

    for (i=0; i<templset->count; i++) {
        const TmplPkt *p1 = &templset->pkts[i];
        TmplPkt *p2 = &result.pkts[i];
        p2->ipv4.packet = MALLOC(2048+p2->ipv4.length);
        memcpy(p2->ipv4.packet, p1->ipv4.packet, p2->ipv4.length);
        p2->ipv6.packet = MALLOC(2048+p2->ipv6.length);
        memcpy(p2->ipv6.packet, p1->ipv6.packet, p2->ipv6.length);
    }

    return result;
}

TmplPkt templ_packet_copy(const TmplPkt *tmpl_pkt)
{
    TmplPkt result;

    memcpy(&result, tmpl_pkt, sizeof(result));

    const TmplPkt *p1 = tmpl_pkt;
    TmplPkt *p2 = &result;
    p2->ipv4.packet = MALLOC(2048+p2->ipv4.length);
    memcpy(p2->ipv4.packet, p1->ipv4.packet, p2->ipv4.length);
    p2->ipv6.packet = MALLOC(2048+p2->ipv6.length);
    memcpy(p2->ipv6.packet, p1->ipv6.packet, p2->ipv6.length);

    return result;
}
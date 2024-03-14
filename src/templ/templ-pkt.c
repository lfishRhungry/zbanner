#include <string.h>

#include "templ-pkt.h"
#include "../util/fine-malloc.h"


/***************************************************************************
 ***************************************************************************/
struct TemplateSet templ_copy(const struct TemplateSet *templset)
{
    struct TemplateSet result;
    unsigned i;

    memcpy(&result, templset, sizeof(result));

    for (i=0; i<templset->count; i++) {
        const struct TemplatePacket *p1 = &templset->pkts[i];
        struct TemplatePacket *p2 = &result.pkts[i];
        p2->ipv4.packet = MALLOC(2048+p2->ipv4.length);
        memcpy(p2->ipv4.packet, p1->ipv4.packet, p2->ipv4.length);
        p2->ipv6.packet = MALLOC(2048+p2->ipv6.length);
        memcpy(p2->ipv6.packet, p1->ipv6.packet, p2->ipv6.length);
    }

    return result;
}

struct TemplatePacket templ_packet_copy(const struct TemplatePacket *tmpl_pkt)
{
    struct TemplatePacket result;

    memcpy(&result, tmpl_pkt, sizeof(result));

    const struct TemplatePacket *p1 = tmpl_pkt;
    struct TemplatePacket *p2 = &result;
    p2->ipv4.packet = MALLOC(2048+p2->ipv4.length);
    memcpy(p2->ipv4.packet, p1->ipv4.packet, p2->ipv4.length);
    p2->ipv6.packet = MALLOC(2048+p2->ipv6.length);
    memcpy(p2->ipv6.packet, p1->ipv6.packet, p2->ipv6.length);

    return result;
}
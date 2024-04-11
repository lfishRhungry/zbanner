#include <stdio.h>
#include <string.h>

#include "templ-arp.h"
#include "../globals.h"
#include "../util-misc/checksum.h"
#include "../util-out/logger.h"
#include "../util-data/data-convert.h"

static size_t
arp_create_by_template_ipv4(
    const struct TemplatePacket *tmpl,
    ipv4address ip_them, ipv4address ip_me,
    unsigned char *px, size_t sizeof_px)
{
    if (tmpl->proto != Tmpl_Type_ARP) {
            LOG(LEVEL_ERROR, "arp_create_by_template_ipv4: need a Tmpl_Type_ARP TemplatePacket.\n");
            return 0;
    }
    unsigned r_len = sizeof_px;

    if (r_len > tmpl->ipv4.length)
        r_len = tmpl->ipv4.length;
    memcpy(px, tmpl->ipv4.packet, r_len);
    px = px + tmpl->ipv4.offset_ip;
    U32_TO_BE(px+14, ip_me);
    U32_TO_BE(px+24, ip_them);

    return r_len;
}

size_t
arp_create_by_template(
    const struct TemplatePacket *tmpl,
    ipaddress ip_them, ipaddress ip_me,
    unsigned char *px, size_t sizeof_px)
{
    if (tmpl->proto != Tmpl_Type_ARP) {
            LOG(LEVEL_ERROR, "arp_create_by_template: need a Tmpl_Type_ARP TemplatePacket.\n");
            return 0;
    }
    
    size_t r_len = 0;
    
    if (ip_them.version == 4) {
        r_len = arp_create_by_template_ipv4(
            tmpl, ip_them.ipv4, ip_me.ipv4, px, sizeof_px);
    } else {
        ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(ip_them);
        LOG(LEVEL_INFO, "arp_create_by_template: cannot generate arp packet for ipv6: %s\n",
            ip_them_fmt.string);
    }

    return r_len;
}

size_t
arp_create_request_packet(
    ipaddress ip_them, ipaddress ip_me,
    unsigned char *px, size_t sizeof_px)
{
    return arp_create_by_template(&global_tmplset->pkts[Tmpl_Type_ARP],
        ip_them, ip_me, px, sizeof_px);
}
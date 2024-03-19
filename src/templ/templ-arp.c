#include <stdio.h>
#include <string.h>

#include "templ-arp.h"
#include "../globals.h"
#include "../util/checksum.h"
#include "../util/logger.h"

static size_t
arp_create_by_template_ipv4(
    const struct TemplatePacket *tmpl,
    ipv4address ip_them, ipv4address ip_me,
    unsigned char *px, size_t sizeof_px)
{
    if (tmpl->proto != Proto_ARP) {
            fprintf(stderr, "arp_create_by_template_ipv4: need a Proto_ARP TemplatePacket.\n");
            return 0;
    }
    unsigned r_len = sizeof_px;

    if (r_len > tmpl->ipv4.length)
        r_len = tmpl->ipv4.length;
    memcpy(px, tmpl->ipv4.packet, r_len);
    px = px + tmpl->ipv4.offset_ip;
    px[14] = (unsigned char)((ip_me >> 24) & 0xFF);
    px[15] = (unsigned char)((ip_me >> 16) & 0xFF);
    px[16] = (unsigned char)((ip_me >>  8) & 0xFF);
    px[17] = (unsigned char)((ip_me >>  0) & 0xFF);
    px[24] = (unsigned char)((ip_them >> 24) & 0xFF);
    px[25] = (unsigned char)((ip_them >> 16) & 0xFF);
    px[26] = (unsigned char)((ip_them >>  8) & 0xFF);
    px[27] = (unsigned char)((ip_them >>  0) & 0xFF);

    return r_len;
}

size_t
arp_create_by_template(
    const struct TemplatePacket *tmpl,
    ipaddress ip_them, ipaddress ip_me,
    unsigned char *px, size_t sizeof_px)
{
    if (tmpl->proto != Proto_ARP) {
            fprintf(stderr, "arp_create_by_template: need a Proto_ARP TemplatePacket.\n");
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
    return arp_create_by_template(&global_tmplset->pkts[Proto_ARP],
        ip_them, ip_me, px, sizeof_px);
}
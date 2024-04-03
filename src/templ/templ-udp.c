/**
 * RFC 768
                      User Datagram Header Format

                  0      7 8     15 16    23 24    31
                 +--------+--------+--------+--------+
                 |     Source      |   Destination   |
                 |      Port       |      Port       |
                 +--------+--------+--------+--------+
                 |                 |                 |
                 |     Length      |    Checksum     |
                 +--------+--------+--------+--------+
                 |
                 |          data octets ...
                 +---------------- ...


                pseudo header

                  0      7 8     15 16    23 24    31
                 +--------+--------+--------+--------+
                 |          source address           |
                 +--------+--------+--------+--------+
                 |        destination address        |
                 +--------+--------+--------+--------+
                 |  zero  |protocol|   UDP length    |
                 +--------+--------+--------+--------+

*/

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "templ-udp.h"
#include "../globals.h"
#include "../util-out/logger.h"
#include "../util-misc/checksum.h"
#include "../util-data/data-convert.h"
#include "../proto/proto-preprocess.h"

static size_t
udp_create_by_template_ipv4(
    struct TemplatePacket *tmpl,
    ipv4address ip_them, unsigned port_them,
    ipv4address ip_me, unsigned port_me,
    unsigned char *payload, size_t payload_length,
    unsigned char *px, size_t sizeof_px)
{
    unsigned offset_ip;
    unsigned offset_tcp;
    uint64_t xsum;
    unsigned xsum2;
    unsigned r_len = sizeof_px;

    memcpy(tmpl->ipv4.packet+tmpl->ipv4.offset_app,
        payload, payload_length);
    tmpl->ipv4.length = tmpl->ipv4.offset_app + payload_length;

    /* Create some shorter local variables to work with */
    if (r_len > tmpl->ipv4.length)
        r_len = tmpl->ipv4.length;
    memcpy(px, tmpl->ipv4.packet, r_len);
    offset_ip      = tmpl->ipv4.offset_ip;
    offset_tcp     = tmpl->ipv4.offset_tcp;
    unsigned ip_id = ip_them ^ port_them;

    /*

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

    /*
     * Fill in the empty fields in the IP header and then re-calculate
     * the checksum.
     */
    {
        unsigned total_length = tmpl->ipv4.length - tmpl->ipv4.offset_ip;
        U16_TO_BE(px+offset_ip+ 2, total_length);
    }
    U16_TO_BE(px+offset_ip+ 4, ip_id);
    U32_TO_BE(px+offset_ip+12, ip_me);
    U32_TO_BE(px+offset_ip+16, ip_them);

    px[offset_ip+10] = (unsigned char)(0);
    px[offset_ip+11] = (unsigned char)(0);

    xsum2 = (unsigned)~checksum_ip_header(px, offset_ip, tmpl->ipv4.length);

    U16_TO_BE(px+offset_ip+10, xsum2);

    /*
     * Now do the checksum for the higher layer protocols
     */
    xsum = 0;
    U16_TO_BE(px+offset_tcp+ 0, port_me);
    U16_TO_BE(px+offset_tcp+ 2, port_them);
    U16_TO_BE(px+offset_tcp+ 4, tmpl->ipv4.length - tmpl->ipv4.offset_app + 8);

    px[offset_tcp+6] = (unsigned char)(0);
    px[offset_tcp+7] = (unsigned char)(0);
    xsum = checksum_udp(px, offset_ip, offset_tcp, tmpl->ipv4.length - offset_tcp);
    xsum = ~xsum;
    U16_TO_BE(px+offset_tcp+ 6, xsum);

    return r_len;
}

static size_t
udp_create_by_template_ipv6(
    struct TemplatePacket *tmpl,
    ipv6address ip_them, unsigned port_them,
    ipv6address ip_me, unsigned port_me,
    unsigned char *payload, size_t payload_length,
    unsigned char *px, size_t sizeof_px)
{
    unsigned offset_ip;
    unsigned offset_tcp;
    uint64_t xsum;
    unsigned r_len = sizeof_px;

    memcpy(tmpl->ipv6.packet+tmpl->ipv6.offset_app,
        payload, payload_length);
    tmpl->ipv6.length = tmpl->ipv6.offset_app + payload_length;

    /* Create some shorter local variables to work with */
    if (r_len > tmpl->ipv6.length)
        r_len = tmpl->ipv6.length;
    memcpy(px, tmpl->ipv6.packet, r_len);
    offset_ip  = tmpl->ipv6.offset_ip;
    offset_tcp = tmpl->ipv6.offset_tcp;
    //ip_id = ip_them ^ port_them ^ seqno;

/*

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |  Next Header  |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                         Source Address                        +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                      Destination Address                      +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
    /*
     * Fill in the empty fields in the IP header and then re-calculate
     * the checksum.
     */
    payload_length = tmpl->ipv6.length - tmpl->ipv6.offset_ip - 40;
    U16_TO_BE(px+offset_ip+ 4, payload_length);
    U64_TO_BE(px+offset_ip+ 8, ip_me.hi);
    U64_TO_BE(px+offset_ip+16, ip_me.lo);
    U64_TO_BE(px+offset_ip+24, ip_them.hi);
    U64_TO_BE(px+offset_ip+32, ip_them.lo);

    /*
     * Now do the checksum for the higher layer protocols
     */
            /* TODO: IPv6 */
    U16_TO_BE(px+offset_tcp+ 0, port_me);
    U16_TO_BE(px+offset_tcp+ 2, port_them);
    U16_TO_BE(px+offset_tcp+ 4, tmpl->ipv6.length - tmpl->ipv6.offset_app + 8);

    px[offset_tcp+6] = (unsigned char)(0);
    px[offset_tcp+7] = (unsigned char)(0);
    xsum = checksum_ipv6(px + offset_ip + 8, px + offset_ip + 24, 17,  tmpl->ipv6.length - offset_tcp, px + offset_tcp);
    U16_TO_BE(px+offset_tcp+ 6, xsum);

    return r_len;
}

size_t
udp_create_by_template(
    struct TemplatePacket *tmpl,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned char *payload, size_t payload_length,
    unsigned char *px, size_t sizeof_px)
{
    if (tmpl->proto != Proto_UDP) {
            fprintf(stderr, "udp_create_by_template: need a Proto_UDP TemplatePacket.\n");
            return 0;
    }

    size_t r_len = 0;

    if (ip_them.version == 4) {
        r_len = udp_create_by_template_ipv4(tmpl,
            ip_them.ipv4, port_them,
            ip_me.ipv4, port_me,
            payload, payload_length, px, sizeof_px);
    } else {
        r_len = udp_create_by_template_ipv6(tmpl,
            ip_them.ipv6, port_them,
            ip_me.ipv6, port_me,
            payload, payload_length, px, sizeof_px);
    }
    return r_len;
}

size_t
udp_create_packet(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned char *payload, size_t payload_length,
    unsigned char *px, size_t sizeof_px)
{
    return udp_create_by_template(&global_tmplset->pkts[Proto_UDP],
        ip_them, port_them, ip_me, port_me,
        payload, payload_length, px, sizeof_px);
}
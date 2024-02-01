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

*/

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "templ-udp.h"
#include "../globals.h"
#include "../util/logger.h"
#include "../util/checksum.h"
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
    offset_ip = tmpl->ipv4.offset_ip;
    offset_tcp = tmpl->ipv4.offset_tcp;
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
        px[offset_ip+2] = (unsigned char)(total_length>>8);
        px[offset_ip+3] = (unsigned char)(total_length>>0);
    }
    px[offset_ip+4] = (unsigned char)(ip_id >> 8);
    px[offset_ip+5] = (unsigned char)(ip_id & 0xFF);
    px[offset_ip+12] = (unsigned char)((ip_me >> 24) & 0xFF);
    px[offset_ip+13] = (unsigned char)((ip_me >> 16) & 0xFF);
    px[offset_ip+14] = (unsigned char)((ip_me >>  8) & 0xFF);
    px[offset_ip+15] = (unsigned char)((ip_me >>  0) & 0xFF);
    px[offset_ip+16] = (unsigned char)((ip_them >> 24) & 0xFF);
    px[offset_ip+17] = (unsigned char)((ip_them >> 16) & 0xFF);
    px[offset_ip+18] = (unsigned char)((ip_them >>  8) & 0xFF);
    px[offset_ip+19] = (unsigned char)((ip_them >>  0) & 0xFF);


    px[offset_ip+10] = (unsigned char)(0);
    px[offset_ip+11] = (unsigned char)(0);

    xsum2 = (unsigned)~checksum_ip_header(px, offset_ip, tmpl->ipv4.length);

    px[offset_ip+10] = (unsigned char)(xsum2 >> 8);
    px[offset_ip+11] = (unsigned char)(xsum2 & 0xFF);


    /*
     * Now do the checksum for the higher layer protocols
     */
    xsum = 0;
    px[offset_tcp+ 0] = (unsigned char)(port_me >> 8);
    px[offset_tcp+ 1] = (unsigned char)(port_me & 0xFF);
    px[offset_tcp+ 2] = (unsigned char)(port_them >> 8);
    px[offset_tcp+ 3] = (unsigned char)(port_them & 0xFF);
    px[offset_tcp+ 4] = (unsigned char)((tmpl->ipv4.length - tmpl->ipv4.offset_app + 8)>>8);
    px[offset_tcp+ 5] = (unsigned char)((tmpl->ipv4.length - tmpl->ipv4.offset_app + 8)&0xFF);

    px[offset_tcp+6] = (unsigned char)(0);
    px[offset_tcp+7] = (unsigned char)(0);
    xsum = checksum_udp(px, offset_ip, offset_tcp, tmpl->ipv4.length - offset_tcp);
    xsum = ~xsum;
    px[offset_tcp+6] = (unsigned char)(xsum >>  8);
    px[offset_tcp+7] = (unsigned char)(xsum >>  0);

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
    offset_ip = tmpl->ipv6.offset_ip;
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
    px[offset_ip+4] = (unsigned char)(payload_length>>8);
    px[offset_ip+5] = (unsigned char)(payload_length>>0);
    px[offset_ip+ 8] = (unsigned char)((ip_me.hi >> 56ULL) & 0xFF);
    px[offset_ip+ 9] = (unsigned char)((ip_me.hi >> 48ULL) & 0xFF);
    px[offset_ip+10] = (unsigned char)((ip_me.hi >> 40ULL) & 0xFF);
    px[offset_ip+11] = (unsigned char)((ip_me.hi >> 32ULL) & 0xFF);
    px[offset_ip+12] = (unsigned char)((ip_me.hi >> 24ULL) & 0xFF);
    px[offset_ip+13] = (unsigned char)((ip_me.hi >> 16ULL) & 0xFF);
    px[offset_ip+14] = (unsigned char)((ip_me.hi >>  8ULL) & 0xFF);
    px[offset_ip+15] = (unsigned char)((ip_me.hi >>  0ULL) & 0xFF);

    px[offset_ip+16] = (unsigned char)((ip_me.lo >> 56ULL) & 0xFF);
    px[offset_ip+17] = (unsigned char)((ip_me.lo >> 48ULL) & 0xFF);
    px[offset_ip+18] = (unsigned char)((ip_me.lo >> 40ULL) & 0xFF);
    px[offset_ip+19] = (unsigned char)((ip_me.lo >> 32ULL) & 0xFF);
    px[offset_ip+20] = (unsigned char)((ip_me.lo >> 24ULL) & 0xFF);
    px[offset_ip+21] = (unsigned char)((ip_me.lo >> 16ULL) & 0xFF);
    px[offset_ip+22] = (unsigned char)((ip_me.lo >>  8ULL) & 0xFF);
    px[offset_ip+23] = (unsigned char)((ip_me.lo >>  0ULL) & 0xFF);

    px[offset_ip+24] = (unsigned char)((ip_them.hi >> 56ULL) & 0xFF);
    px[offset_ip+25] = (unsigned char)((ip_them.hi >> 48ULL) & 0xFF);
    px[offset_ip+26] = (unsigned char)((ip_them.hi >> 40ULL) & 0xFF);
    px[offset_ip+27] = (unsigned char)((ip_them.hi >> 32ULL) & 0xFF);
    px[offset_ip+28] = (unsigned char)((ip_them.hi >> 24ULL) & 0xFF);
    px[offset_ip+29] = (unsigned char)((ip_them.hi >> 16ULL) & 0xFF);
    px[offset_ip+30] = (unsigned char)((ip_them.hi >>  8ULL) & 0xFF);
    px[offset_ip+31] = (unsigned char)((ip_them.hi >>  0ULL) & 0xFF);

    px[offset_ip+32] = (unsigned char)((ip_them.lo >> 56ULL) & 0xFF);
    px[offset_ip+33] = (unsigned char)((ip_them.lo >> 48ULL) & 0xFF);
    px[offset_ip+34] = (unsigned char)((ip_them.lo >> 40ULL) & 0xFF);
    px[offset_ip+35] = (unsigned char)((ip_them.lo >> 32ULL) & 0xFF);
    px[offset_ip+36] = (unsigned char)((ip_them.lo >> 24ULL) & 0xFF);
    px[offset_ip+37] = (unsigned char)((ip_them.lo >> 16ULL) & 0xFF);
    px[offset_ip+38] = (unsigned char)((ip_them.lo >>  8ULL) & 0xFF);
    px[offset_ip+39] = (unsigned char)((ip_them.lo >>  0ULL) & 0xFF);

    /*
     * Now do the checksum for the higher layer protocols
     */
            /* TODO: IPv6 */
    px[offset_tcp+ 0] = (unsigned char)(port_me >> 8);
    px[offset_tcp+ 1] = (unsigned char)(port_me & 0xFF);
    px[offset_tcp+ 2] = (unsigned char)(port_them >> 8);
    px[offset_tcp+ 3] = (unsigned char)(port_them & 0xFF);
    px[offset_tcp+ 4] = (unsigned char)((tmpl->ipv6.length - tmpl->ipv6.offset_app + 8)>>8);
    px[offset_tcp+ 5] = (unsigned char)((tmpl->ipv6.length - tmpl->ipv6.offset_app + 8)&0xFF);

    px[offset_tcp+6] = (unsigned char)(0);
    px[offset_tcp+7] = (unsigned char)(0);
    xsum = checksum_ipv6(px + offset_ip + 8, px + offset_ip + 24, 17,  tmpl->ipv6.length - offset_tcp, px + offset_tcp);
    px[offset_tcp+6] = (unsigned char)(xsum >>  8);
    px[offset_tcp+7] = (unsigned char)(xsum >>  0);

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
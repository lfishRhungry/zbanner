#include <stdio.h>
#include <string.h>

#include "templ-icmp.h"
#include "../globals.h"
#include "../util/checksum.h"

/* Generic ICMPv4 according to RFC792
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             unused                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/* Generic ICMPv6 according to RFC4443
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |     Code      |          Checksum             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                         Message Body                          +
      |                                                               |
*/

/* echo or echo reply ICMP(v4/v6) according to RFC792 and RFC4443.
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-

   So we set cookie on `Identifier` and `Sequence Number` fields when echoing.
*/

static size_t
icmp_create_by_template_ipv4(
    const struct TemplatePacket *tmpl,
    ipv4address ip_them, ipv4address ip_me,
    unsigned cookie, uint16_t ip_id, uint8_t ttl,
    unsigned char *px, size_t sizeof_px)
{
    unsigned offset_ip;
    unsigned offset_tcp;
    uint64_t xsum;
    unsigned xsum2;
    unsigned r_len = sizeof_px;


    /* Create some shorter local variables to work with */
    if (r_len > tmpl->ipv4.length)
        r_len = tmpl->ipv4.length;
    memcpy(px, tmpl->ipv4.packet, r_len);
    offset_ip = tmpl->ipv4.offset_ip;
    offset_tcp = tmpl->ipv4.offset_tcp;

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

    px[offset_ip+8] = (unsigned char)(ttl);

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

    px[offset_tcp+ 4] = (unsigned char)(cookie >> 24);
    px[offset_tcp+ 5] = (unsigned char)(cookie >> 16);
    px[offset_tcp+ 6] = (unsigned char)(cookie >>  8);
    px[offset_tcp+ 7] = (unsigned char)(cookie >>  0);
    xsum = (uint64_t)tmpl->ipv4.checksum_tcp
            + (uint64_t)cookie;
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = ~xsum;
    px[offset_tcp+2] = (unsigned char)(xsum >>  8);
    px[offset_tcp+3] = (unsigned char)(xsum >>  0);

    return r_len;
}

static size_t
icmp_create_by_template_ipv6(
    const struct TemplatePacket *tmpl,
    ipv6address ip_them, ipv6address ip_me,
    unsigned cookie, uint8_t ttl,
    unsigned char *px, size_t sizeof_px)
{
    unsigned offset_ip;
    unsigned offset_tcp;
    uint64_t xsum;
    unsigned payload_length;

    unsigned r_len = sizeof_px;

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

    px[offset_ip+7] = (unsigned char)(ttl);

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
    px[offset_tcp+ 4] = (unsigned char)(cookie >> 24);
    px[offset_tcp+ 5] = (unsigned char)(cookie >> 16);
    px[offset_tcp+ 6] = (unsigned char)(cookie >>  8);
    px[offset_tcp+ 7] = (unsigned char)(cookie >>  0);
    xsum = checksum_ipv6(px + offset_ip + 8, px + offset_ip + 24, 58,  tmpl->ipv6.length - offset_tcp, px + offset_tcp);
    px[offset_tcp+2] = (unsigned char)(xsum >>  8);
    px[offset_tcp+3] = (unsigned char)(xsum >>  0);

    return r_len;
}

size_t
icmp_create_by_template(
    const struct TemplatePacket *tmpl,
    ipaddress ip_them, ipaddress ip_me,
    unsigned cookie, uint16_t ip_id, uint8_t ttl,
    unsigned char *px, size_t sizeof_px)
{
    if (tmpl->proto != Proto_ICMP_ping
        && tmpl->proto != Proto_ICMP_timestamp) {
            fprintf(stderr, "icmp_create_by_template: need a Proto_ICMP_ping or Proto_ICMP_timestamp TemplatePacket.\n");
            return 0;
    }

    size_t r_len = 0;

    if (ip_them.version == 4) {
        r_len = icmp_create_by_template_ipv4(tmpl, ip_them.ipv4, ip_me.ipv4,
            cookie, ip_id, ttl, px, sizeof_px);
    } else {
        r_len = icmp_create_by_template_ipv6(tmpl, ip_them.ipv6, ip_me.ipv6,
            cookie, ttl, px, sizeof_px);
    }
    return r_len;
}

size_t
icmp_create_echo_packet(
    ipaddress ip_them, const ipaddress ip_me,
    unsigned cookie, uint16_t ip_id, uint8_t ttl,
    unsigned char *px, size_t sizeof_px)
{
    return icmp_create_by_template(&global_tmplset->pkts[Proto_ICMP_ping],
        ip_them, ip_me, cookie, ip_id, ttl, px, sizeof_px);
}

size_t
icmp_create_timestamp_packet(
    ipaddress ip_them, const ipaddress ip_me,
    unsigned cookie, uint16_t ip_id, uint8_t ttl,
    unsigned char *px, size_t sizeof_px)
{
    return icmp_create_by_template(&global_tmplset->pkts[Proto_ICMP_timestamp],
        ip_them, ip_me, cookie, ip_id, ttl, px, sizeof_px);
}

unsigned
get_icmp_cookie(const struct PreprocessedInfo *parsed,const unsigned char *px)
{
    unsigned cookie =  px[parsed->transport_offset+4]<<24
                        | px[parsed->transport_offset+5]<<16
                        | px[parsed->transport_offset+6]<<8
                        | px[parsed->transport_offset+7]<<0;
    return cookie;
}

unsigned
get_icmp_type(const struct PreprocessedInfo *parsed) {
    return parsed->port_src;
}

unsigned
get_icmp_code(const struct PreprocessedInfo *parsed) {
    return parsed->port_dst;
}

/***************************************************************************
 ***************************************************************************/
int
parse_icmp_port_unreachable(const unsigned char *transport_px, unsigned length,
    ipaddress *r_ip_them, unsigned *r_port_them,
    ipaddress *r_ip_me, unsigned *r_port_me,
    unsigned *r_ip_proto)
{
    const unsigned char *ip_header_in_icmp = transport_px + 8;
    unsigned data_length_in_icmp = length - (ip_header_in_icmp - transport_px);

    if (ip_header_in_icmp[0]>>4 == 0B0100) {
        /*ipv4*/
        r_ip_them->version = 4;
        r_ip_me->version = 4;

        r_ip_me->ipv4 = ip_header_in_icmp[12]<<24
            | ip_header_in_icmp[13]<<16
            | ip_header_in_icmp[14]<<8
            | ip_header_in_icmp[15];
        r_ip_them->ipv4 = ip_header_in_icmp[16]<<24
            | ip_header_in_icmp[17]<<16
            | ip_header_in_icmp[18]<<8
            | ip_header_in_icmp[19];
        
        if (ip_header_in_icmp[9]==6) {
            *r_ip_proto = Proto_TCP;
        } else if (ip_header_in_icmp[9]==17) {
            *r_ip_proto = Proto_UDP;
        } else {
            return 0;
        }

        ip_header_in_icmp += (ip_header_in_icmp[0]&0xF)<<2;
        data_length_in_icmp -= (ip_header_in_icmp[0]&0xF)<<2;

        if (data_length_in_icmp < 4)
            return 0;

        *r_port_me = ip_header_in_icmp[0]<<8 | ip_header_in_icmp[1];
        *r_port_them = ip_header_in_icmp[2]<<8 | ip_header_in_icmp[3];

    } else if (ip_header_in_icmp[0]>>4 == 0B0110) {
        /*ipv6*/
        r_ip_them->version = 6;
        r_ip_me->version = 6;

        r_ip_me->ipv6.hi = 0ULL
                            | (uint64_t)ip_header_in_icmp[8] << 56ULL
                            | (uint64_t)ip_header_in_icmp[9] << 48ULL
                            | (uint64_t)ip_header_in_icmp[10] << 40ULL
                            | (uint64_t)ip_header_in_icmp[11] << 32ULL
                            | (uint64_t)ip_header_in_icmp[12] << 24ULL
                            | (uint64_t)ip_header_in_icmp[13] << 16ULL
                            | (uint64_t)ip_header_in_icmp[14] <<  8ULL
                            | (uint64_t)ip_header_in_icmp[15] <<  0ULL;
        r_ip_me->ipv6.lo = 0ULL
                            | (uint64_t)ip_header_in_icmp[16] << 56ULL
                            | (uint64_t)ip_header_in_icmp[17] << 48ULL
                            | (uint64_t)ip_header_in_icmp[18] << 40ULL
                            | (uint64_t)ip_header_in_icmp[19] << 32ULL
                            | (uint64_t)ip_header_in_icmp[20] << 24ULL
                            | (uint64_t)ip_header_in_icmp[21] << 16ULL
                            | (uint64_t)ip_header_in_icmp[22] <<  8ULL
                            | (uint64_t)ip_header_in_icmp[23] <<  0ULL;

        r_ip_them->ipv6.hi = 0ULL
                            | (uint64_t)ip_header_in_icmp[24] << 56ULL
                            | (uint64_t)ip_header_in_icmp[25] << 48ULL
                            | (uint64_t)ip_header_in_icmp[26] << 40ULL
                            | (uint64_t)ip_header_in_icmp[27] << 32ULL
                            | (uint64_t)ip_header_in_icmp[28] << 24ULL
                            | (uint64_t)ip_header_in_icmp[29] << 16ULL
                            | (uint64_t)ip_header_in_icmp[30] <<  8ULL
                            | (uint64_t)ip_header_in_icmp[31] <<  0ULL;
        r_ip_them->ipv6.lo = 0ULL
                            | (uint64_t)ip_header_in_icmp[32] << 56ULL
                            | (uint64_t)ip_header_in_icmp[33] << 48ULL
                            | (uint64_t)ip_header_in_icmp[34] << 40ULL
                            | (uint64_t)ip_header_in_icmp[35] << 32ULL
                            | (uint64_t)ip_header_in_icmp[36] << 24ULL
                            | (uint64_t)ip_header_in_icmp[37] << 16ULL
                            | (uint64_t)ip_header_in_icmp[38] <<  8ULL
                            | (uint64_t)ip_header_in_icmp[39] <<  0ULL;

        if (ip_header_in_icmp[6]==6) {
            *r_ip_proto = Proto_TCP;
        } else if (ip_header_in_icmp[6]==17) {
            *r_ip_proto = Proto_UDP;
        } else {
            return 0;
        }

        ip_header_in_icmp += ((ip_header_in_icmp[4]<<8)|(ip_header_in_icmp[5]));
        data_length_in_icmp -= ((ip_header_in_icmp[4]<<8)|(ip_header_in_icmp[5]));

        if (data_length_in_icmp < 4)
            return 0;

        *r_port_me = ip_header_in_icmp[0]<<8 | ip_header_in_icmp[1];
        *r_port_them = ip_header_in_icmp[2]<<8 | ip_header_in_icmp[3];
    }

    return 0;
}
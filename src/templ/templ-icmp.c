#include <stdio.h>
#include <string.h>

#include "templ-icmp.h"
#include "../globals.h"
#include "../util-misc/checksum.h"
#include "../util-data/data-convert.h"

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

/*
ICMPv4 Timestamp or Timestamp Reply Message according to RFC792

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |      Code     |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Originate Timestamp                                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Receive Timestamp                                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Transmit Timestamp                                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
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
    offset_ip  = tmpl->ipv4.offset_ip;
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

    unsigned total_length = tmpl->ipv4.length - tmpl->ipv4.offset_ip;
    U16_TO_BE(px+offset_ip+2, total_length);

    U16_TO_BE(px+offset_ip+4, ip_id);

    px[offset_ip+8] = (unsigned char)(ttl);

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

    U32_TO_BE(px+offset_tcp+4, cookie);

    xsum = (uint64_t)tmpl->ipv4.checksum_tcp
            + (uint64_t)cookie;
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = ~xsum;
    U16_TO_BE(px+offset_tcp+2, xsum);

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
    U16_TO_BE(px+offset_ip+4, payload_length);

    px[offset_ip+7] = (unsigned char)(ttl);

    U64_TO_BE(px+offset_ip+ 8, ip_me.hi);
    U64_TO_BE(px+offset_ip+16, ip_me.lo);

    U64_TO_BE(px+offset_ip+24, ip_them.hi);
    U64_TO_BE(px+offset_ip+32, ip_them.lo);

    /*
     * Now do the checksum for the higher layer protocols
     */
    /* TODO: IPv6 */
    U32_TO_BE(px+offset_tcp+4, cookie);
    xsum = checksum_ipv6(px + offset_ip + 8, px + offset_ip + 24, 58,  tmpl->ipv6.length - offset_tcp, px + offset_tcp);
    U16_TO_BE(px+offset_tcp+2, xsum);

    return r_len;
}

size_t
icmp_create_by_template(
    const struct TemplatePacket *tmpl,
    ipaddress ip_them, ipaddress ip_me,
    unsigned cookie, uint16_t ip_id, uint8_t ttl,
    unsigned char *px, size_t sizeof_px)
{
    if (tmpl->proto != Proto_ICMP_ECHO
        && tmpl->proto != Proto_ICMP_TS) {
            LOG(LEVEL_ERROR, "icmp_create_by_template: need a Proto_ICMP_ECHO or Proto_ICMP_TS TemplatePacket.\n");
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
    return icmp_create_by_template(&global_tmplset->pkts[Proto_ICMP_ECHO],
        ip_them, ip_me, cookie, ip_id, ttl, px, sizeof_px);
}

size_t
icmp_create_timestamp_packet(
    ipaddress ip_them, const ipaddress ip_me,
    unsigned cookie, uint16_t ip_id, uint8_t ttl,
    unsigned char *px, size_t sizeof_px)
{
    return icmp_create_by_template(&global_tmplset->pkts[Proto_ICMP_TS],
        ip_them, ip_me, cookie, ip_id, ttl, px, sizeof_px);
}

unsigned
get_icmp_cookie(const struct PreprocessedInfo *parsed,const unsigned char *px)
{
    return BE_TO_U32(px+parsed->transport_offset+4);
}

/***************************************************************************
 ***************************************************************************/
bool
parse_icmp_port_unreachable(const unsigned char *transport_px, unsigned length,
    ipaddress *r_ip_them, unsigned *r_port_them,
    ipaddress *r_ip_me, unsigned *r_port_me,
    unsigned *r_ip_proto)
{
    const unsigned char *ip_header_in_icmp = transport_px + 8;
    unsigned data_length_in_icmp           = length - (ip_header_in_icmp - transport_px);
    unsigned ipv4_header_len;

    if (ip_header_in_icmp[0]>>4 == 0B0100) {
        /*ipv4*/
        r_ip_them->version = 4;
        r_ip_me->version   = 4;

        r_ip_me->ipv4   = BE_TO_U32(ip_header_in_icmp+12);
        r_ip_them->ipv4 = BE_TO_U32(ip_header_in_icmp+16);

        if (ip_header_in_icmp[9]==6) {
            *r_ip_proto = Proto_TCP;
        } else if (ip_header_in_icmp[9]==17) {
            *r_ip_proto = Proto_UDP;
        } else {
            return false;
        }

        ipv4_header_len      = (ip_header_in_icmp[0]&0xF)<<2;
        ip_header_in_icmp   += ipv4_header_len;
        data_length_in_icmp -= ipv4_header_len;

        if (data_length_in_icmp < 4)
            return false;

        *r_port_me   = BE_TO_U16(ip_header_in_icmp);
        *r_port_them = BE_TO_U16(ip_header_in_icmp+2);

    } else if (ip_header_in_icmp[0]>>4 == 0B0110) {
        /*ipv6*/
        r_ip_them->version = 6;
        r_ip_me->version   = 6;

        r_ip_me->ipv6.hi     = BE_TO_U64(ip_header_in_icmp+ 8);
        r_ip_me->ipv6.lo     = BE_TO_U64(ip_header_in_icmp+16);
        r_ip_them->ipv6.hi   = BE_TO_U64(ip_header_in_icmp+24);
        r_ip_them->ipv6.lo   = BE_TO_U64(ip_header_in_icmp+32);

        if (ip_header_in_icmp[6]==6) {
            *r_ip_proto = Proto_TCP;
        } else if (ip_header_in_icmp[6]==17) {
            *r_ip_proto = Proto_UDP;
        } else {
            return false;
        }

        /*length of ipv6 header is fixed*/
        ip_header_in_icmp   += 40;
        data_length_in_icmp -= 40;

        if (data_length_in_icmp < 4)
            return false;

        *r_port_me   = BE_TO_U16(ip_header_in_icmp);
        *r_port_them = BE_TO_U16(ip_header_in_icmp+2);
    }

    return true;
}

/***************************************************************************
 ***************************************************************************/
unsigned
get_icmp_port_unreachable_proto(const unsigned char *transport_px, unsigned length)
{
    const unsigned char *ip_header_in_icmp = transport_px + 8;

    if (ip_header_in_icmp[0]>>4 == 0B0100) {
        
        if (ip_header_in_icmp[9]==6) {
            return Proto_TCP;
        } else if (ip_header_in_icmp[9]==17) {
            return Proto_UDP;
        }

    } else if (ip_header_in_icmp[0]>>4 == 0B0110) {

        if (ip_header_in_icmp[6]==6) {
            return Proto_TCP;
        } else if (ip_header_in_icmp[6]==17) {
            return Proto_UDP;
        }
    }

    return 0;
}
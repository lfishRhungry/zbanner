/**
        SCTP Node A |<-------- Network transport ------->| SCTP Node B
       _____________                                      _____________
      |  SCTP User  |                                    |  SCTP User  |
      | Application |                                    | Application |
      |-------------|                                    |-------------|
      |    SCTP     |                                    |    SCTP     |
      |  Transport  |                                    |  Transport  |
      |   Service   |                                    |   Service   |
      |-------------|                                    |-------------|
      |             |One or more    ----      One or more|             |
      | IP Network  |IP address      \/        IP address| IP Network  |
      |   Service   |appearances     /\       appearances|   Service   |
      |_____________|               ----                 |_____________|

  The SCTP packet format is shown below:

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                        Common Header                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          Chunk #1                             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           ...                                 |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          Chunk #n                             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  SCTP Common Header Format

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Source Port Number        |     Destination Port Number   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Verification Tag                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Checksum                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  SCTP common chunk

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Chunk Type  | Chunk  Flags  |        Chunk Length           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       \                                                               \
       /                          Chunk Value                          /
       \                                                               \
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 SCTP INIT chunk
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Type = 1    |  Chunk Flags  |      Chunk Length             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Initiate Tag                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           Advertised Receiver Window Credit (a_rwnd)          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Number of Outbound Streams   |  Number of Inbound Streams    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          Initial TSN                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       \                                                               \
       /              Optional/Variable-Length Parameters              /
       \                                                               \
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   SCTP INIT ACK chunk

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Type = 2    |  Chunk Flags  |      Chunk Length             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Initiate Tag                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |              Advertised Receiver Window Credit                |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Number of Outbound Streams   |  Number of Inbound Streams    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          Initial TSN                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       \                                                               \
       /              Optional/Variable-Length Parameters              /
       \                                                               \
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "templ-sctp.h"
#include "../globals.h"
#include "../util-out/logger.h"
#include "../util-misc/checksum.h"
#include "../util-data/data-convert.h"
#include "../proto/proto-preprocess.h"

static size_t
sctp_create_by_template_ipv4(
    struct TemplatePacket *tmpl,
    ipv4address ip_them, unsigned port_them,
    ipv4address ip_me, unsigned port_me,
    unsigned init_tag,
    unsigned char *px, size_t sizeof_px)
{
    unsigned offset_ip;
    unsigned offset_tcp;
    uint64_t xsum;
    unsigned xsum2;

    unsigned ip_id = ip_them ^ port_them ^ init_tag;
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
    {
        unsigned total_length = tmpl->ipv4.length - tmpl->ipv4.offset_ip;
        px[offset_ip+2] = (unsigned char)(total_length>>8);
        px[offset_ip+3] = (unsigned char)(total_length>>0);
    }
    U16_EQUAL_TO_BE(px+offset_ip+ 4, ip_id);
    U32_EQUAL_TO_BE(px+offset_ip+12, ip_me);
    U32_EQUAL_TO_BE(px+offset_ip+16, ip_them);

    px[offset_ip+10] = (unsigned char)(0);
    px[offset_ip+11] = (unsigned char)(0);

    xsum2 = (unsigned)~checksum_ip_header(px, offset_ip, tmpl->ipv4.length);

    U16_EQUAL_TO_BE(px+offset_ip+10, xsum2);


    /*
     * Now do the checksum for the higher layer protocols
     */
    xsum = 0;
    U16_EQUAL_TO_BE(px+offset_tcp+ 0, port_me);
    U16_EQUAL_TO_BE(px+offset_tcp+ 2, port_them);
    U32_EQUAL_TO_BE(px+offset_tcp+16, init_tag);

    xsum = checksum_sctp(px + offset_tcp, tmpl->ipv4.length - offset_tcp);
    U32_EQUAL_TO_BE(px+offset_tcp+ 8, xsum);

    return r_len;
}

static size_t
sctp_create_by_template_ipv6(
    struct TemplatePacket *tmpl,
    ipv6address ip_them, unsigned port_them,
    ipv6address ip_me, unsigned port_me,
    unsigned init_tag,
    unsigned char *px, size_t sizeof_px)
{
    unsigned offset_ip;
    unsigned offset_tcp;
    uint64_t xsum;

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
    unsigned payload_length = tmpl->ipv6.length - tmpl->ipv6.offset_ip - 40;
    U16_TO_BE(px+offset_ip+4, payload_length);

    U64_TO_BE(px+offset_ip+ 8, ip_me.hi);
    U64_TO_BE(px+offset_ip+16, ip_me.lo);

    U64_TO_BE(px+offset_ip+24, ip_them.hi);
    U64_TO_BE(px+offset_ip+32, ip_them.lo);

        /* TODO: IPv6 */
    U16_TO_BE(px+offset_tcp+ 0, port_me);
    U16_TO_BE(px+offset_tcp+ 2, port_them);
    U32_TO_BE(px+offset_tcp+16, init_tag);

    xsum = checksum_sctp(px + offset_tcp, tmpl->ipv6.length - offset_tcp);
    U32_TO_BE(px+offset_tcp+ 8, xsum);

    return r_len;
}

size_t
sctp_create_by_template(
    struct TemplatePacket *tmpl,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned init_tag,
    unsigned char *px, size_t sizeof_px)
{
    if (tmpl->tmpl_type != Tmpl_Type_SCTP) {
            LOG(LEVEL_ERROR, "sctp_create_by_template: need a Tmpl_Type_SCTP TemplatePacket.\n");
            return 0;
    }

    size_t r_len = 0;

    if (ip_them.version == 4) {
        r_len = sctp_create_by_template_ipv4(tmpl,
            ip_them.ipv4, port_them,
            ip_me.ipv4, port_me,
            init_tag,
            px, sizeof_px);
    } else {
        r_len = sctp_create_by_template_ipv6(tmpl,
            ip_them.ipv6, port_them,
            ip_me.ipv6, port_me,
            init_tag,
            px, sizeof_px);
    }
    return r_len;
}

size_t
sctp_create_packet(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned init_tag,
    unsigned char *px, size_t sizeof_px)
{
    return sctp_create_by_template(&global_tmplset->pkts[Tmpl_Type_SCTP],
        ip_them, port_them, ip_me, port_me,
        init_tag, px, sizeof_px);
}
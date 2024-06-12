#include <stdio.h>
#include <string.h>

#include "templ-ndp.h"
#include "../globals.h"
#include "../util-misc/checksum.h"
#include "../util-data/data-convert.h"

/* ICMPv6 NDP Nerghbor Solicitation according to RFC4861
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |     Code      |          Checksum             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           Reserved                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +                                                               +
     |                                                               |
     +                       Target Address                          +
     |                                                               |
     +                                                               +
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Options ...
     +-+-+-+-+-+-+-+-+-+-+-+-

      Destination Address:
                     Either the solicited-node multicast address
                     corresponding to the target address, or the target
                     address. (The latter is for verifying the reachability
                     of a neighbor and We must know its mac addr.)

      Target Address: The IP address of the target of the solicitation.
                      It MUST NOT be a multicast address.

   Possible options:

      Source link-layer address
                     The link-layer address for the sender.  MUST NOT be
                     included when the source IP address is the
                     unspecified address.  Otherwise, on link layers
                     that have addresses this option MUST be included in
                     multicast solicitations and SHOULD be included in
                     unicast solicitations.


*/

/* ICMPv6 NDP Nerghbor Advertisement according to RFC4861
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |     Code      |          Checksum             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |R|S|O|                     Reserved                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                                                               +
      |                                                               |
      +                       Target Address                          +
      |                                                               |
      +                                                               +
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   Options ...
      +-+-+-+-+-+-+-+-+-+-+-+-

      Destination Address
                     For solicited advertisements, the Source Address of
                     an invoking Neighbor Solicitation or, if the
                     solicitation's Source Address is the unspecified
                     address, the all-nodes multicast address.

                     For unsolicited advertisements typically the all-
                     nodes multicast address.

      Target Address
                     For solicited advertisements, the Target Address
                     field in the Neighbor Solicitation message that
                     prompted this advertisement.  For an unsolicited
                     advertisement, the address whose link-layer address
                     has changed.  The Target Address MUST NOT be a
                     multicast address.

      R              Router flag.  When set, the R-bit indicates that
                     the sender is a router.  The R-bit is used by
                     Neighbor Unreachability Detection to detect a
                     router that changes to a host.

      S              Solicited flag.  When set, the S-bit indicates that
                     the advertisement was sent in response to a
                     Neighbor Solicitation from the Destination address.
                     The S-bit is used as a reachability confirmation
                     for Neighbor Unreachability Detection.  It MUST NOT
                     be set in multicast advertisements or in
                     unsolicited unicast advertisements.

      O              Override flag.  When set, the O-bit indicates that
                     the advertisement should override an existing cache
                     entry and update the cached link-layer address.
                     When it is not set the advertisement will not
                     update a cached link-layer address though it will
                     update an existing Neighbor Cache entry for which
                     no link-layer address is known.  It SHOULD NOT be
                     set in solicited advertisements for anycast
                     addresses and in solicited proxy advertisements.
                     It SHOULD be set in other solicited advertisements
                     and in unsolicited advertisements.

   Possible options:

      Target link-layer address
                     The link-layer address for the target, i.e., the
                     sender of the advertisement.  This option MUST be
                     included on link layers that have addresses when
                     responding to multicast solicitations.  When
                     responding to a unicast Neighbor Solicitation this
                     option SHOULD be included.

                     The option MUST be included for multicast
                     solicitations in order to avoid infinite Neighbor
                     Solicitation "recursion" when the peer node does
                     not have a cache entry to return a Neighbor
                     Advertisements message.  When responding to unicast
                     solicitations, the option can be omitted since the
                     sender of the solicitation has the correct link-
                     layer address; otherwise, it would not be able to
                     send the unicast solicitation in the first place.
                     However, including the link-layer address in this
                     case adds little overhead and eliminates a
                     potential race condition where the sender deletes
                     the cached link-layer address prior to receiving a
                     response to a previous solicitation.

*/

/* ICMPv6 NDP Option Format according to RFC4861
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Type      |    Length     |              ...              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                              ...                              ~
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Source/Target Link-layer Address

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |    Length     |    Link-Layer Address ...
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

static size_t
ndp_create_ns_by_template_ipv6(
    const struct TemplatePacket *tmpl,
    ipv6address ip_them, ipv6address ip_me, macaddress_t src_mac,
    uint8_t ttl, unsigned char *px, size_t sizeof_px)
{
    if (tmpl->tmpl_type != Tmpl_Type_NDP_NS) {
            LOG(LEVEL_ERROR, "ndp_create_by_template_ipv6: need a Tmpl_Type_NDP_NS TemplatePacket.\n");
            return 0;
    }

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
    /*set dst mac as multicast addr*/
    px[0] = 0x33;
    px[1] = 0x33;
    px[2] = 0xFF;
    px[3] = (unsigned char)((ip_them.lo >> 16ULL) & 0xFF);
    px[4] = (unsigned char)((ip_them.lo >>  8ULL) & 0xFF);
    px[5] = (unsigned char)((ip_them.lo >>  0ULL) & 0xFF);

    /*
     * Fill in the empty fields in the IP header and then re-calculate
     * the checksum.
     */
    payload_length = tmpl->ipv6.length - tmpl->ipv6.offset_ip - 40;
    U16_TO_BE(px+offset_ip+4, payload_length);

    px[offset_ip+7] = (unsigned char)(ttl);

    U64_TO_BE(px+offset_ip+ 8, ip_me.hi);
    U64_TO_BE(px+offset_ip+16, ip_me.lo);

    /*set solicited-node addr*/
    px[offset_ip+24] = 0xFF;
    px[offset_ip+25] = 0x02;
    px[offset_ip+26] = 0x00;
    px[offset_ip+27] = 0x00;
    px[offset_ip+28] = 0x00;
    px[offset_ip+29] = 0x00;
    px[offset_ip+30] = 0x00;
    px[offset_ip+31] = 0x00;

    px[offset_ip+32] = 0x00;
    px[offset_ip+33] = 0x00;
    px[offset_ip+34] = 0x00;
    px[offset_ip+35] = 0x01;
    px[offset_ip+36] = 0xFF;
    px[offset_ip+37] = (unsigned char)((ip_them.lo >> 16ULL) & 0xFF);
    px[offset_ip+38] = (unsigned char)((ip_them.lo >>  8ULL) & 0xFF);
    px[offset_ip+39] = (unsigned char)((ip_them.lo >>  0ULL) & 0xFF);

    /*set Target Address in NDP*/
    U64_TO_BE(px+offset_tcp+ 8, ip_them.hi);
    U64_TO_BE(px+offset_tcp+16, ip_them.lo);

    /*set src link addr in NDP*/
    px[offset_tcp+26] = src_mac.addr[0];
    px[offset_tcp+27] = src_mac.addr[1];
    px[offset_tcp+28] = src_mac.addr[2];
    px[offset_tcp+29] = src_mac.addr[3];
    px[offset_tcp+30] = src_mac.addr[4];
    px[offset_tcp+31] = src_mac.addr[5];

    /*
     * Now do the checksum for the higher layer protocols
     */
    xsum = checksum_ipv6(px + offset_ip + 8, px + offset_ip + 24, 58,  tmpl->ipv6.length - offset_tcp, px + offset_tcp);
    px[offset_tcp+2] = (unsigned char)(xsum >>  8);
    px[offset_tcp+3] = (unsigned char)(xsum >>  0);

    return r_len;
}

size_t
ndp_create_ns_packet(
    ipaddress ip_them, ipaddress ip_me, macaddress_t src_mac,
    uint8_t ttl, unsigned char *px, size_t sizeof_px)
{
    /*just for IPv6*/
    if (ip_them.version == 4) return 0;

    return ndp_create_ns_by_template_ipv6(&global_tmplset->pkts[Tmpl_Type_NDP_NS],
        ip_them.ipv6, ip_me.ipv6, src_mac, ttl, px, sizeof_px);
}

bool ndp_is_solicited_advertise(ipv6address ip_them,
    const unsigned char *px, unsigned icmpv6_offset)
{
    if (U64_EQUAL_TO_BE(px+icmpv6_offset+8, ip_them.hi)
        && U64_EQUAL_TO_BE(px+icmpv6_offset+16, ip_them.lo))
        return true;

    return false;
}
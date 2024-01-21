#include <stdlib.h>

#include "tcp_syn_scan.h"
// #include "../templ/templ-pkt.h"
// #include "../templ/templ-tcp-hdr.h"
#include "../util/mas-safefunc.h"
#include "../util/mas-malloc.h"
#include "../cookie.h"

extern struct ScanModule TcpSynScan;

static unsigned char default_tcp_template[] =
    "\0\1\2\3\4\5"  /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb"  /* Ethernet: source */
    "\x08\x00"      /* Ethernet type: IPv4 */
    "\x45"          /* IP type */
    "\x00"
    "\x00\x2c"      /* total length = 40 bytes */
    "\x00\x00"      /* identification */
    "\x00\x00"      /* fragmentation flags */
    "\xFF\x06"      /* TTL=255, proto=TCP */
    "\xFF\xFF"      /* checksum */
    "\0\0\0\0"      /* source address */
    "\0\0\0\0"      /* destination address */

    "\0\0"          /* source port */
    "\0\0"          /* destination port */
    "\0\0\0\0"      /* sequence number */
    "\0\0\0\0"      /* ACK number */
    "\x60"          /* header length */
    "\x02"          /* SYN */
    "\x04\x01"      /* window fixed to 1024 */
    "\xFF\xFF"      /* checksum */
    "\x00\x00"      /* urgent pointer */
      "\x02\x04\x05\xb4"  /* opt [mss 1460] h/t @IvreRocks */
;

static int
tcpsyn_global_init(
    struct TemplatePacket *tmpl_pkt, macaddress_t source_mac,
    macaddress_t router_mac_ipv4, macaddress_t router_mac_ipv6,
    struct PayloadsUDP *udp_payloads, struct PayloadsUDP *oproto_payloads, 
    int data_link, const struct TemplateOptions *templ_opts)
{
    //we do not malloc space internally for `packet` of tmp_pkt and init it.
    //we just set features.
    unsigned char *buf;
    size_t length;

    length = sizeof(default_tcp_template) - 1;
    buf = MALLOC(length);
    memcpy(buf, default_tcp_template, length);

    templ_tcp_apply_options(&buf, &length, templ_opts);
    //malloc space internally for `packet` of tmp_pkt and init it.
    _template_init(tmpl_pkt, source_mac, router_mac_ipv4, router_mac_ipv6,
        buf, length, data_link);

    free(buf);

    return EXIT_SUCCESS;
}

static int
tcpsyn_make_packet_ipv4(
    struct TemplatePacket *tmpl_pkt,
    ipv4address ip_them, unsigned port_them,
    ipv4address ip_me, unsigned port_me,
    uint64_t entropy, unsigned index,
    unsigned char *px, unsigned px_length, size_t *r_length)
{
    unsigned offset_ip;
    unsigned offset_tcp;
    uint64_t xsum;
    unsigned xsum2;
    unsigned seqno;
    
    *r_length = px_length;
    seqno = get_cookie_ipv4(ip_them, port_them, ip_me, port_me, entropy);

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

    if (*r_length > tmpl_pkt->ipv4.length)
        *r_length = tmpl_pkt->ipv4.length;
    memcpy(px, tmpl_pkt->ipv4.packet, *r_length);

    template_fill_target_ipv4_hdr(tmpl_pkt, ip_them, ip_me, entropy, px, *r_length);

    offset_tcp = tmpl_pkt->ipv4.offset_tcp;

    /*
     * Now do the checksum for the higher layer protocols
     */
    xsum = 0;

    px[offset_tcp+ 0] = (unsigned char)(port_me >> 8);
    px[offset_tcp+ 1] = (unsigned char)(port_me & 0xFF);
    px[offset_tcp+ 2] = (unsigned char)(port_them >> 8);
    px[offset_tcp+ 3] = (unsigned char)(port_them & 0xFF);
    px[offset_tcp+ 4] = (unsigned char)(seqno >> 24);
    px[offset_tcp+ 5] = (unsigned char)(seqno >> 16);
    px[offset_tcp+ 6] = (unsigned char)(seqno >>  8);
    px[offset_tcp+ 7] = (unsigned char)(seqno >>  0);

    xsum += (uint64_t)tmpl_pkt->ipv4.checksum_tcp
            + (uint64_t)ip_me
            + (uint64_t)ip_them
            + (uint64_t)port_me
            + (uint64_t)port_them
            + (uint64_t)seqno;
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = ~xsum;

    px[offset_tcp+16] = (unsigned char)(xsum >>  8);
    px[offset_tcp+17] = (unsigned char)(xsum >>  0);
}

static int
tcpsyn_make_packet_ipv6(
    struct TemplatePacket *tmpl_pkt,
    ipv6address ip_them, unsigned port_them,
    ipv6address ip_me, unsigned port_me,
    uint64_t entropy, unsigned index,
    unsigned char *px, unsigned px_length, size_t *r_length)
{
    unsigned offset_tcp;
    unsigned offset_ip;
    uint64_t xsum;
    unsigned seqno;
    
    *r_length = px_length;
    seqno = get_cookie_ipv6(ip_them, port_them, ip_me, port_me, entropy);

    /* Create some shorter local variables to work with */
    if (*r_length > tmpl_pkt->ipv6.length)
        *r_length = tmpl_pkt->ipv6.length;
    memcpy(px, tmpl_pkt->ipv6.packet, *r_length);

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

    template_fill_target_ipv6_hdr(tmpl_pkt, ip_them, ip_me, entropy, px, *r_length);

    offset_tcp = tmpl_pkt->ipv6.offset_tcp;
    offset_ip = tmpl_pkt->ipv6.offset_ip;

    /*
     * Now do the checksum for the higher layer protocols
     */
    px[offset_tcp+ 0] = (unsigned char)(port_me >> 8);
    px[offset_tcp+ 1] = (unsigned char)(port_me & 0xFF);
    px[offset_tcp+ 2] = (unsigned char)(port_them >> 8);
    px[offset_tcp+ 3] = (unsigned char)(port_them & 0xFF);
    px[offset_tcp+ 4] = (unsigned char)(seqno >> 24);
    px[offset_tcp+ 5] = (unsigned char)(seqno >> 16);
    px[offset_tcp+ 6] = (unsigned char)(seqno >>  8);
    px[offset_tcp+ 7] = (unsigned char)(seqno >>  0);

    xsum = checksum_ipv6(px + offset_ip + 8, px + offset_ip + 24, 6, tmpl_pkt->ipv6.length - offset_tcp, px + offset_tcp);
    px[offset_tcp+16] = (unsigned char)(xsum >>  8);
    px[offset_tcp+17] = (unsigned char)(xsum >>  0);
}

struct ScanModule TcpSynScan = {
    .name = "tcpsyn",
    .description =
        "TcpSynScan sends a TCP SYN packet to target port. Expect a SYNACK "
        "response to believe the port is open or a RST for closed.\n"
        "TcpSynScan is the default ScanModule.\n",

    .global_init_cb = tcpsyn_global_init,
    .rx_thread_init_cb = NULL,
    .tx_thread_init_cb = NULL,

    .make_packet_ipv4_cb = NULL,
    .make_packet_ipv6_cb = NULL,

    .validate_packet_cb = NULL,
    .dedup_packet_cb = NULL,
    .handle_packet_cb = NULL,
    .response_packet_cb = NULL,

    .close_cb = NULL,
};
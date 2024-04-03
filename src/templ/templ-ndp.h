#ifndef TEMPL_NDP_H
#define TEMPL_NDP_H

#include "templ-pkt.h"
#include "templ-icmp.h"
#include "../util-misc/cross.h"
#include "../massip/massip-addr.h"
#include "../proto/proto-preprocess.h"

#define NDP_NA_FLAG_ROUTER    0B10000000
#define NDP_NA_FLAG_SOLICITED 0B01000000
#define NDP_NA_FLAG_OVERRIDE  0B00100000

#define NDP_NA_FLAGS(px,i) (px[(i)+4])

#define NDP_NA_HAS_FLAG(px,i,flag) ((NDP_NA_FLAGS((px),(i)) & (flag)) == (flag))


size_t
ndp_create_ns_packet(
    ipaddress ip_them, ipaddress ip_me, macaddress_t src_mac,
    uint8_t ttl, unsigned char *px, size_t sizeof_px);


/**
 * Check if an NA is for solicitation by checking the target IP in IP header is
 * equal to target ip in ICMPv6
*/
bool ndp_is_solicited_advertise(ipv6address ip_them,
    const unsigned char *px, unsigned icmpv6_offset);


#endif
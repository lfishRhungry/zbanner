#ifndef TEMPL_ARP_H
#define TEMPL_ARP_H

#include "templ-pkt.h"
#include "../util/bool.h" /* <stdbool.h> */
#include "../massip/massip-addr.h"
#include "../proto/proto-preprocess.h"

#define ARP_OPCODE_REQUEST 1
#define ARP_OPCODE_REPLY   2

/**
 * NOTE: We just generate valid ARP request for IPv4
 * @param tmpl TemplatePacket of ARP.
 * @return len of packet generated. Zero if IPv6.
*/
size_t
arp_create_by_template(
    const struct TemplatePacket *tmpl,
    ipaddress ip_them, ipaddress ip_me,
    unsigned char *px, size_t sizeof_px);

/**
 * NOTE: We just generate valid ARP request for IPv4.
 * @return len of packet generated. Zero if IPv6.
*/
size_t
arp_create_request_packet(
    ipaddress ip_them, ipaddress ip_me,
    unsigned char *px, size_t sizeof_px);

#endif
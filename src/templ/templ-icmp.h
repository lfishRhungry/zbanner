#ifndef TEMPL_ICMP_H
#define TEMPL_ICMP_H

#include "templ-pkt.h"
#include "../util/bool.h" /* <stdbool.h> */
#include "../massip/massip-addr.h"
#include "../proto/proto-preprocess.h"


/**
 * @param cookie we set cookie in the `other data of icmp header`(unused).
 * Its better to set to zero if not icmp echo.
 * @param ip_id just for ipv4 and could set it randomly.
 * @param ttl it is for ipv4's ttl or ipv6's hop limit.
 * @return len of packet generated.
*/
size_t
icmp_create_by_template(
    const struct TemplatePacket *tmpl,
    ipaddress ip_them, ipaddress ip_me,
    unsigned cookie, uint16_t ip_id, uint8_t ttl,
    unsigned char *px, size_t sizeof_px);

/**
 * This is a wrapped func that uses global_tmplset to create icmp echo packet.
 * @param cookie we set cookie in the `other data of icmp header`(unused).
 * Its better to set to zero if not icmp echo.
 * @param ip_id just for ipv4 and could set it randomly.
 * @param ttl it is for ipv4's ttl or ipv6's hop limit.
 * @return len of packet generated.
*/
size_t
icmp_create_echo_packet(
    ipaddress ip_them, ipaddress ip_me,
    unsigned cookie, uint16_t ip_id, uint8_t ttl,
    unsigned char *px, size_t sizeof_px);

/**
 * This is a wrapped func that uses global_tmplset to create icmp icmp packet.
 * @param cookie we set cookie in the `other data of icmp header`(unused).
 * Its better to set to zero if not icmp echo.
 * @param ip_id just for ipv4 and could set it randomly.
 * @param ttl it is for ipv4's ttl or ipv6's hop limit.
 * @return len of packet generated.
*/
size_t
icmp_create_timestamp_packet(
    ipaddress ip_them, const ipaddress ip_me,
    unsigned cookie, uint16_t ip_id, uint8_t ttl,
    unsigned char *px, size_t sizeof_px);

/**
 * try to get cookie in the `other data of icmp header`(unused).
 * it is meaningful just with icmp echo.
*/
unsigned
try_get_cookie_from_icmp(struct PreprocessedInfo *parsed,const unsigned char *px);

#endif
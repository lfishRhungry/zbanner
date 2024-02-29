#ifndef TEMPL_ICMP_H
#define TEMPL_ICMP_H

#include "templ-pkt.h"
#include "../util/bool.h" /* <stdbool.h> */
#include "../massip/massip-addr.h"
#include "../proto/proto-preprocess.h"

/**
 * I list some often used type and code of ICMP
*/

#define ICMPv4_TYPE_ECHO_REPLY                       0
#define ICMPv4_CODE_ECHO_REPLY                       0

#define ICMPv4_TYPE_ERR                              3
#define ICMPv4_CODE_ERR_NET_UNREACHABLE              0
#define ICMPv4_CODE_ERR_HOST_UNREACHABLE             1
#define ICMPv4_CODE_ERR_PROTOCOL_UNREACHABLE         2
#define ICMPv4_CODE_ERR_PORT_UNREACHABLE             3

#define ICMPv4_TYPE_QUENCH                           4
#define ICMPv4_CODE_QUENCH                           0

#define ICMPv4_TYPE_ECHO_REQUEST                     8
#define ICMPv4_CODE_ECHO_REQUEST                     0

#define ICMPv4_TYPE_TTL_EXCEEDED                     11
#define ICMPv4_CODE_TTL_EXCEEDED                     0

#define ICMPv4_TYPE_TIMESTAMP_MSG                    13
#define ICMPv4_CODE_TIMESTAMP_MSG                    0

#define ICMPv4_TYPE_TIMESTAMP_REPLY                  14
#define ICMPv4_CODE_TIMESTAMP_REPLY                  0

#define ICMPv6_TYPE_ERR                              1
#define ICMPv6_CODE_ERR_NO_ROUTE_TO_DST              0
#define ICMPv6_CODE_ERR_COMM_PROHIBITED              1
#define ICMPv6_CODE_ERR_BEYOND_SCOPE                 2
#define ICMPv6_CODE_ERR_ADDR_UNREACHABLE             3
#define ICMPv6_CODE_ERR_PORT_UNREACHABLE             4
#define ICMPv6_CODE_ERR_SRC_ADDR_FAILED              5
#define ICMPv6_CODE_ERR_REJECT_ROUTE_TO_DST          6

#define ICMPv6_TYPE_HOPLIMIT_EXCEEDED                3
#define ICMPv6_CODE_HOPLIMIT_EXCEEDED                0

#define ICMPv6_TYPE_ECHO_REQUEST                     128
#define ICMPv6_CODE_ECHO_REQUEST                     0

#define ICMPv6_TYPE_ECHO_REPLY                       129
#define ICMPv6_CODE_ECHO_REPLY                       0

/**
 * @param tmpl TemplatePacket of ICMP.
 * @param cookie we set cookie on `Identifier` and `Sequence Number` fields.
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
 * @param cookie we set cookie on `Identifier` and `Sequence Number` fields.
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
 * @param cookie we set cookie on `Identifier` and `Sequence Number` fields.
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
 * Try to get cookie from `Identifier` and `Sequence Number` fields.
*/
unsigned
get_icmp_cookie(const struct PreprocessedInfo *parsed,const unsigned char *px);

unsigned
get_icmp_type(const struct PreprocessedInfo *parsed);

unsigned
get_icmp_code(const struct PreprocessedInfo *parsed);

/**
 * @return TRUE if parse successfully
*/
int
parse_icmp_port_unreachable(const unsigned char *transport_px, unsigned length,
    ipaddress *r_ip_them, unsigned *r_port_them,
    ipaddress *r_ip_me, unsigned *r_port_me,
    unsigned *r_ip_proto);

/**
 * @return Proto_TCP or Proto_UDP or 0 for nothing.
*/
unsigned
get_icmp_port_unreachable_proto(const unsigned char *transport_px, unsigned length);

#endif
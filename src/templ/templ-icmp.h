#ifndef TEMPL_ICMP_H
#define TEMPL_ICMP_H

#include "templ-pkt.h"
#include "../target/target-ipaddress.h"

/**
 * I list some often used type and code of ICMP
 */

#define ICMPv4_TYPE_ECHO_REPLY 0
#define ICMPv4_CODE_ECHO_REPLY 0

#define ICMPv4_TYPE_ERR                      3
#define ICMPv4_CODE_ERR_NET_UNREACHABLE      0
#define ICMPv4_CODE_ERR_HOST_UNREACHABLE     1
#define ICMPv4_CODE_ERR_PROTOCOL_UNREACHABLE 2
#define ICMPv4_CODE_ERR_PORT_UNREACHABLE     3

#define ICMPv4_TYPE_QUENCH 4
#define ICMPv4_CODE_QUENCH 0

#define ICMPv4_TYPE_ECHO_REQUEST 8
#define ICMPv4_CODE_ECHO_REQUEST 0

#define ICMPv4_TYPE_TTL_EXCEEDED 11
#define ICMPv4_CODE_TTL_EXCEEDED 0

#define ICMPv4_TYPE_TIMESTAMP_MSG 13
#define ICMPv4_CODE_TIMESTAMP_MSG 0

#define ICMPv4_TYPE_TIMESTAMP_REPLY 14
#define ICMPv4_CODE_TIMESTAMP_REPLY 0

#define ICMPv6_TYPE_ERR                     1
#define ICMPv6_CODE_ERR_NO_ROUTE_TO_DST     0
#define ICMPv6_CODE_ERR_COMM_PROHIBITED     1
#define ICMPv6_CODE_ERR_BEYOND_SCOPE        2
#define ICMPv6_CODE_ERR_ADDR_UNREACHABLE    3
#define ICMPv6_CODE_ERR_PORT_UNREACHABLE    4
#define ICMPv6_CODE_ERR_SRC_ADDR_FAILED     5
#define ICMPv6_CODE_ERR_REJECT_ROUTE_TO_DST 6

#define ICMPv6_TYPE_HOPLIMIT_EXCEEDED 3
#define ICMPv6_CODE_HOPLIMIT_EXCEEDED 0

#define ICMPv6_TYPE_ECHO_REQUEST 128
#define ICMPv6_CODE_ECHO_REQUEST 0

#define ICMPv6_TYPE_ECHO_REPLY 129
#define ICMPv6_CODE_ECHO_REPLY 0

#define ICMPv6_TYPE_RS 133
#define ICMPv6_CODE_RS 0

#define ICMPv6_TYPE_RA 134
#define ICMPv6_CODE_RA 0

#define ICMPv6_TYPE_NS 135
#define ICMPv6_CODE_NS 0

#define ICMPv6_TYPE_NA 136
#define ICMPv6_CODE_NA 0

/**
 * @param tmpl TemplatePacket of ICMP ECHO.
 * @return len of packet generated.
 */
size_t icmp_echo_create_by_template(const TmplPkt *tmpl, ipaddress ip_them,
                                    ipaddress ip_me, uint16_t identifier,
                                    uint16_t sequence, uint16_t ip_id,
                                    uint8_t ttl, unsigned char *payload,
                                    size_t payload_length, unsigned char *px,
                                    size_t sizeof_px);

/**
 * This is a wrapped func that uses global_tmplset to create icmp echo packet.
 * @return len of packet generated.
 */
size_t icmp_echo_create_packet(ipaddress ip_them, const ipaddress ip_me,
                               uint16_t identifier, uint16_t sequence,
                               uint16_t ip_id, uint8_t ttl,
                               unsigned char *payload, size_t payload_length,
                               unsigned char *px, size_t sizeof_px);

/**
 * This is a wrapped func that uses global_tmplset to create icmp timestamp
 * packet.
 * @return len of packet generated.
 */
size_t icmp_timestamp_create_by_template(const TmplPkt *tmpl, ipaddress ip_them,
                                         ipaddress ip_me, uint16_t identifier,
                                         uint16_t sequence, uint16_t ip_id,
                                         uint8_t ttl, unsigned origin_time,
                                         unsigned recv_time,
                                         unsigned trans_time, unsigned char *px,
                                         size_t sizeof_px);

/**
 * This is a wrapped func that uses global_tmplset to create icmp timestamp
 * packet.
 * @return len of packet generated.
 */
size_t icmp_timestamp_create_packet(ipaddress ip_them, const ipaddress ip_me,
                                    uint16_t identifier, uint16_t sequence,
                                    uint16_t ip_id, uint8_t ttl,
                                    unsigned origin_time, unsigned recv_time,
                                    unsigned trans_time, unsigned char *px,
                                    size_t sizeof_px);

/**
 * Get detail info from icmp port unreachable message payload.
 * NOTE: We can do this by preprocessing the embedded ICMP payload. But the
 * preprocess function parses successfully only when the packet content is
 * complete. However, ICMP unreachable message only contains part of original
 * packets sometimes. This function could handle in this case.
 *
 * @param transport_px packet data over IP
 * @param length len of transport_px
 * @param r_ip_them for ret ip_them
 * @param r_port_them for ret port_them
 * @param r_ip_me for ret ip_me
 * @param r_port_me for ret port_me
 * @param r_icmp_proto for ret ip protocol number, 6 for tcp or 17 for udp
 * @param r_app_px app layer pointer in udp of icmp
 * @return TRUE if parse successfully
 */
bool parse_icmp_port_unreachable(const unsigned char *transport_px,
                                 unsigned length, ipaddress *r_ip_them,
                                 unsigned *r_port_them, ipaddress *r_ip_me,
                                 unsigned *r_port_me, unsigned *r_icmp_proto);

/**
 * get upper proto number of icmp if exists.
 * @param transport_px packet data over IP
 * @return IP Protocol number
 */
unsigned get_icmp_upper_proto(const unsigned char *transport_px);

#endif
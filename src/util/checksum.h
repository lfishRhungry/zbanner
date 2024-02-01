/*
    Calculates Internet checksums for protocols like TCP/IP.

    Author: Robert David Graham
    Copyright: 2020
    License: The MIT License (MIT)
    Dependencies: none
*/
#ifndef CHECKSUM_H
#define CHECKSUM_H
#include <stddef.h>

/**
 * Calculate a checksum for IPv4 packets.
 * @param ip_src
 *      The source IPv4 address, represented a standard way,
 *      as a 32-bit integer in host byte order.
 * @param ip_dst
 *      The destination IPv4 address, represented as a 32-bit integer in host byte order.
 * @param ip_proto
 *      A value of 6 for TCP or 17 for UDP.
 * @param payload_length
 *      The length of the IP packet payload, meaning, everything after the IPv4 header.
 *      In other words, it's the "total length" field of the IP packet minus the
 *      length of the IP header.
 * @param payload
 *      A pointer to the aforementioned payload (a pointer to the first byte past the
 *      IP header). Note that the calculation skips the checksum field, so the payload
 *      we use is everything but the 2 bytes in the checksum field. Thus, due to the 
 *      quirkiness of Internet protocols, the result of this calculation should end
 *      up equally the value of the checksum field.
 * @return
 *      the calculated checksum, which should equal the checksum found in the payload
 */
unsigned 
checksum_ipv4(unsigned ip_src, unsigned ip_dst,
    unsigned ip_proto, size_t payload_length, const void *payload);

unsigned 
checksum_ipv6(const unsigned char *ip_src, const unsigned char *ip_dst,
    unsigned ip_proto, size_t payload_length, const void *payload);

/***************************************************************************
 * Checksum the IP header. This is a "partial" checksum, so we
 * don't reverse the bits ~.
 ***************************************************************************/
unsigned
checksum_ip_header(const unsigned char *px, unsigned offset, unsigned max_offset);

unsigned
checksum_icmp(const unsigned char *px,
    unsigned offset_icmp, size_t icmp_length);

unsigned
checksum_udp(const unsigned char *px, unsigned offset_ip,
    unsigned offset_tcp, size_t tcp_length);

unsigned
checksum_tcp(const unsigned char *px, unsigned offset_ip,
    unsigned offset_tcp, size_t tcp_length);

unsigned
checksum_sctp(const void *vbuffer, size_t length);

#endif

/*
    Calculates Internet checksums for protocols like TCP/IP.

    Author: Robert David Graham
    Copyright: 2020
    License: The MIT License (MIT)
    Dependencies: none

    Modified: sharkocha 2024
*/
#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stddef.h>

/**
 * Calculate a checksum of general uppler-layer protocol for IPv4.
 * NOTE: Just support some protocols.
 *
 * @param payload_length payload of IP packet.
 * @param payload
 *      A pointer to the aforementioned payload (a pointer to the first byte
 * past the IP header). Note that the calculation skips the checksum field, so
 * the payload we use is everything but the 2 bytes in the checksum field.
 * Thus, due to the quirkiness of Internet protocols, the result of this
 * calculation should end up equally the value of the checksum field.
 * @return the calculated checksum, which should equal the checksum found in the
 * payload
 */
unsigned checksum_ipv4_upper(unsigned ip_src, unsigned ip_dst,
                             unsigned ip_proto, size_t payload_length,
                             const void *payload);

/**
 * Calculate a checksum of general uppler-layer protocol for IPv6.
 * NOTE: Just support some protocols.
 *
 * @param payload_length payload of IP packet.
 * @param payload
 *      A pointer to the aforementioned payload (a pointer to the first byte
 * past the IP header). Note that the calculation skips the checksum field, so
 * the payload we use is everything but the 2 bytes in the checksum field.
 * Thus, due to the quirkiness of Internet protocols, the result of this
 * calculation should end up equally the value of the checksum field.
 * @return the calculated checksum, which should equal the checksum found in the
 * payload
 */
unsigned checksum_ipv6_upper(const unsigned char *ip_src,
                             const unsigned char *ip_dst, unsigned ip_proto,
                             size_t payload_length, const void *payload);

/***************************************************************************
 * Checksum the IP header.
 * NOTE: Just IPv4 has checksum in header.
 * @param offset ip layer offset.
 * @param max_offset max offset ip layer used to do border check.
 ***************************************************************************/
unsigned checksum_ipv4_header(const unsigned char *px, unsigned offset_ip,
                              unsigned max_offset);

unsigned checksum_ipv4_icmp(const unsigned char *px, unsigned offset_icmp,
                            size_t icmp_length);

unsigned checksum_ipv4_udp(const unsigned char *px, unsigned offset_ip,
                           unsigned offset_udp, size_t udp_length);

unsigned checksum_ipv4_tcp(const unsigned char *px, unsigned offset_ip,
                           unsigned offset_tcp, size_t tcp_length);

/**
 * SCTP use CRC32 to do checksum and non-reletive with IP layer or version.
 */
unsigned checksum_sctp(const void *offset_sctp, size_t sctp_length);

int checksum_selftest();

#endif

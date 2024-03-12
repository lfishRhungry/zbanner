/**
 * Store the declare of struct and corresponding funcs
*/
#ifndef TCP_PKT_H
#define TCP_PKT_H

#include <stdint.h>

enum TemplateProtocol {
    Proto_TCP,
    Proto_TCP_SYN, /*convenient to set options for packets with syn flag*/
    Proto_UDP,
    Proto_SCTP,
    Proto_ICMP_ping,
    Proto_ICMP_timestamp,
    Proto_ARP,
    Proto_NDP_ns,
    Proto_Count
};
/**
 * Describes a packet template. The scan packets we transmit are based on a
 * a template containing most of the data, and we fill in just the necessary
 * bits, like the destination IP address and port
 */
struct TemplatePacket {
    struct {
        unsigned length;
        unsigned offset_ip;
        unsigned offset_tcp;
        unsigned offset_app;
        unsigned char *packet;
        unsigned checksum_ip;
        unsigned checksum_tcp;
        unsigned ip_id;
    } ipv4;
    struct {
        unsigned length;
        unsigned offset_ip;
        unsigned offset_tcp;
        unsigned offset_app;
        unsigned char *packet;
        unsigned checksum_ip;
        unsigned checksum_tcp;
        unsigned ip_id;
    } ipv6;
    enum TemplateProtocol proto;
    struct PayloadsUDP *payloads;
};

/**
 * We can run multiple types of scans (TCP, UDP, etc.) at the same
 * time. Therefore, instead of one packet prototype for all scans, we have
 * a set of prototypes/templates.
 */
struct TemplateSet
{
    unsigned count;
    uint64_t entropy;
    struct TemplatePacket pkts[Proto_Count];
};

struct TemplateSet templ_copy(const struct TemplateSet *templset);

struct TemplatePacket templ_packet_copy(const struct TemplatePacket *tmpl_pkt);

#endif
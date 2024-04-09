/**
 * Store the declare of struct and corresponding funcs
*/
#ifndef TCP_PKT_H
#define TCP_PKT_H

#include <stdint.h>

#include "../util-out/logger.h"

enum TemplateProtocol {
    Proto_TCP,
    Proto_TCP_SYN,   /*convenient to set options for packets with syn flag*/
    Proto_UDP,
    Proto_SCTP,
    Proto_ICMP_ECHO,
    Proto_ICMP_TS,
    Proto_ARP,
    Proto_NDP_NS,
    Proto_Count
};

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
};

struct TemplateSet
{
    unsigned count;
    uint64_t entropy;
    struct TemplatePacket pkts[Proto_Count];
};

struct TemplateSet templ_copy(const struct TemplateSet *templset);

struct TemplatePacket templ_packet_copy(const struct TemplatePacket *tmpl_pkt);

#endif
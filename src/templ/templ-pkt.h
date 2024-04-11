/**
 * Store the declare of struct and corresponding funcs
*/
#ifndef TCP_PKT_H
#define TCP_PKT_H

#include <stdint.h>

#include "../util-out/logger.h"

enum TemplateType {
    Tmpl_Type_TCP,
    Tmpl_Type_TCP_SYN,   /*convenient to set options for packets with syn flag*/
    Tmpl_Type_UDP,
    Tmpl_Type_SCTP,
    Tmpl_Type_ICMP_ECHO,
    Tmpl_Type_ICMP_TS,
    Tmpl_Type_ARP,
    Tmpl_Type_NDP_NS,
    Tmpl_Type_Count
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
    enum TemplateType proto;
};

struct TemplateSet
{
    unsigned count;
    uint64_t entropy;
    struct TemplatePacket pkts[Tmpl_Type_Count];
};

struct TemplateSet templ_copy(const struct TemplateSet *templset);

struct TemplatePacket templ_packet_copy(const struct TemplatePacket *tmpl_pkt);

#endif
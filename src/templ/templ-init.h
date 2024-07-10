#ifndef TEMPL_INIT_H
#define TEMPL_INIT_H
#include <stdio.h>
#include <stdint.h>

#include "../massip/massip-addr.h"
#include "templ-pkt.h"

typedef struct TemplateOptions TmplOpt;

/**
 * Initialize the "template" packets. As we spew out probes, we simply make
 * minor adjustments to the template, such as changing the target IP
 * address or port number
 *
 * @param templset
 *      The template we are creating.
 * @param source_ip
 *      Our own IP address that we send packets from. The caller will have
 *      retrieved this automatically from the network interface/adapter, or
 *      the user will have set this with --source-ip parameter.
 * @param source_mac
 *      Our own MAC address. Gotten automatically from the network adapter,
 *      or on the commandline with --source-mac parameter
 * @param router_mac
 *      The MAC address of the local router/gateway, which will be placed in
 *      the Ethernet destination address field. This is gotten by ARPing
 *      the local router, or by --router-mac configuration parameter.
 * @param data_link
 *      The OSI layer 2 protocol, as defined in stub-pcap-dlt.h standard.
 */
void
template_packet_init(
    TmplSet *templset,
    macaddress_t source_mac,
    macaddress_t router_mac_ipv4,
    macaddress_t router_mac_ipv6,
    int data_link,
    uint64_t entropy,
    const TmplOpt *templ_opts);


/***************************************************************************
 * Overwrites the Window of default tcp syn template
 ***************************************************************************/
void template_set_tcp_syn_window_of_default(unsigned window);

/***************************************************************************
 * Overwrites the Window of default tcp template
 ***************************************************************************/
void template_set_tcp_window_of_default(unsigned window);

/***************************************************************************
 * Overwrites the TTL of all packet in templateset both IPv4&IPv6
 ***************************************************************************/
void template_set_ttl(TmplSet *tmplset, unsigned ttl);

/***************************************************************************
 * Overwrites the TTL of the templatepacket both IPv4&IPv6
 ***************************************************************************/
void template_packet_set_ttl(TmplPkt *tmpl_pkt, unsigned ttl);

/***************************************************************************
 * Overwrites the vlan of all packet in templateset
 ***************************************************************************/
void template_set_vlan(TmplSet *tmplset, unsigned vlan);

/***************************************************************************
 * Overwrites the vlan of the templatepacket
 ***************************************************************************/
void template_packet_set_vlan(TmplPkt *tmpl_pkt, unsigned vlan);

int template_selftest();

#endif

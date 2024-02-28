#ifndef TEMPL_INIT_H
#define TEMPL_INIT_H
#include <stdio.h>
#include <stdint.h>

#include "../massip/massip-addr.h"
#include "templ-pkt.h"

struct PayloadsUDP;
struct TemplateOptions;

/**
 * Does a regression test of this module.
 * @return
 *      1 on failure
 *      0 on success
 */
int template_selftest(void);

/**
 * transfer port from blackrock random algo to real port
 * and get what protocol this port belong to.
 * @param port port from blackrock random algo
 * @return enum TemplateProtocol or zero if invalid.
*/
unsigned
get_real_protocol_and_port(unsigned *port);

struct TemplatePayload {
    unsigned length;
    unsigned checksum;
    unsigned char buf[1500];
};

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
 *      The OSI layer 2 protocol, as defined in <pcap.h> standard.
 *       1 = Ethernet
 *      12 = Raw IP (no data link)
 */
void
template_packet_init(
    struct TemplateSet *templset,
    macaddress_t source_mac,
    macaddress_t router_mac_ipv4,
    macaddress_t router_mac_ipv6,
    struct PayloadsUDP *udp_payloads,
    struct PayloadsUDP *oproto_payloads,
    int data_link,
    uint64_t entropy,
    const struct TemplateOptions *templ_opts);

/**
 * Sets the target/destination IP address of the packet, the destination port
 * number, and other bits of interest about the packet, such as a unique
 * sequence number. The template can contain things like IP or TCP options
 * with specific values. The program contains several built-in templates,
 * but they can also be read from a file.
 *
 * @param templset
 *      A template created by "template_packet_init()" and further modified
 *      by various configuration parameters.
 * @param ip
 *      The target/destination IPv4 address.
 * @param port
 *      The TCP port number, or port number from another protocol that will
 *      be shifted into the appropriate range. We actually build six base
 *      templates, one for each of these six protocols.
 *      [     0.. 65535] = TCP port number
 *      [ 65536..131071] = UDP port number
 *      [131072..196607] = SCTP port number
 *      [     196608   ] = ICMP
 *      [     196609   ] = ARP
 *      [     196610   ] = IP
 *      [      more    ] = custom
 * @param seqno
 *      On TCP, this will be the desired sequence number, which the caller
 *      will create from SYN-cookies. Other protocols may use this in a
 *      different manner. For example, if the UDP port is 161, then
 *      this will be the transaction ID of the SNMP request template.
 */
void
template_set_target_ipv4(
    struct TemplateSet *templset,
    ipv4address ip_them, unsigned port_them,
    ipv4address ip_me, unsigned port_me,
    unsigned seqno,
    unsigned char *px, size_t sizeof_px, size_t *r_length);

void
template_set_target_ipv6(
    struct TemplateSet *templset,
    ipv6address ip_them, unsigned port_them,
    ipv6address ip_me, unsigned port_me,
    unsigned seqno,
    unsigned char *px, size_t sizeof_px, size_t *r_length);


/***************************************************************************
 * Overwrites the Window of default tcp syn template
 ***************************************************************************/
void template_set_tcp_syn_window_of_default(unsigned window);

/***************************************************************************
 * Overwrites the Window of default tcp template
 ***************************************************************************/
void template_set_tcp_window_of_default(unsigned window);

/***************************************************************************
 * Overwrites the TTL of all packet in templateset
 ***************************************************************************/
void template_set_ttl(struct TemplateSet *tmplset, unsigned ttl);

/***************************************************************************
 * Overwrites the TTL of the templatepacket
 ***************************************************************************/
void template_packet_set_ttl(struct TemplatePacket *tmpl_pkt, unsigned ttl);

/***************************************************************************
 * Overwrites the vlan of all packet in templateset
 ***************************************************************************/
void template_set_vlan(struct TemplateSet *tmplset, unsigned vlan);

/***************************************************************************
 * Overwrites the vlan of the templatepacket
 ***************************************************************************/
void template_packet_set_vlan(struct TemplatePacket *tmpl_pkt, unsigned vlan);

#endif

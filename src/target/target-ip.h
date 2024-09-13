/*
    Born from Masscan
    Modified by sharkocha 2024
*/
#ifndef TARGET_IP_H
#define TARGET_IP_H
#include <stddef.h>
#include "target-rangesv4.h"
#include "target-rangesv6.h"

typedef struct Target_IPs_Ports {
    struct RangeList  ipv4;
    struct Range6List ipv6;

    /**
     * The ports we are scanning for. The user can specify repeated ports
     * and overlapping ranges, but we'll deduplicate them, scanning ports
     * only once.
     * NOTE: TCP ports are stored 0-64k, but UDP ports are stored in the
     * range 64k-128k, thus, allowing us to scan both at the same time.
     */
    struct RangeList ports;

    /**
     * Used internally to differentiate between indexes selecting an
     * IPv4 address and higher ones selecting an IPv6 address.
     */
    uint64_t ipv4_index_threshold;

    uint64_t count_ports;
    uint64_t count_ipv4s;
    uint64_t count_ipv6s;
} TargetIP;

/**
 * For showing ip protocol and diffing port type.
 * Ref:
 * https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 */
#define IP_PROTO_HOPOPT         0 /*IPv6 Hop-by-Hop Option*/
#define IP_PROTO_ICMP           1 /*Internet Control Message*/
#define IP_PROTO_IGMP           2 /*Internet Group Management*/
#define IP_PROTO_GGP            3 /*Gateway-to-Gateway*/
#define IP_PROTO_IPv4           4 /*IPv4 encapsulation*/
#define IP_PROTO_TCP            6 /*Transmission Control*/
#define IP_PROTO_EGP            8 /*Exterior Gateway Protocol*/
/*any private interior gateway (used by Cisco for their IGRP)*/
#define IP_PROTO_IGP            9
#define IP_PROTO_UDP            17  /*User Datagram*/
#define IP_PROTO_IPv6           41  /*IPv6 encapsulation*/
#define IP_PROTO_IPv6_Route     43  /*Routing Header for IPv6*/
#define IP_PROTO_IPv6_Frag      44  /*Fragment Header for IPv6*/
#define IP_PROTO_IDRP           45  /*Inter-Domain Routing Protocol*/
#define IP_PROTO_GRE            47  /*Generic Routing Encapsulation*/
#define IP_PROTO_Min_IPv4       55  /*Minimal IPv4 Encapsulation (for mobile)*/
#define IP_PROTO_IPv6_ICMP      58  /*ICMP for IPv6*/
#define IP_PROTO_IPv6_NoNxt     59  /*No Next Header for IPv6*/
#define IP_PROTO_IPv6_Opts      60  /*Destination Options for IPv6*/
#define IP_PROTO_OSPFIGP        89  /*OSPF*/
#define IP_PROTO_ETHERIP        97  /*Ethernet-within-IP Encapsulation*/
#define IP_PROTO_L2TP           115 /*Layer Two Tunneling Protocol*/
#define IP_PROTO_ISIS_over_IPv4 124
#define IP_PROTO_SCTP           132 /*Stream Control Transmission Protocol*/
#define IP_PROTO_MPLS_in_IP     137
#define IP_PROTO_Other          255 /*For unregisted here or unknown type*/

const char *ip_proto_to_string(unsigned ip_proto);

/**
 * Count the total number of targets in a scan. This is calculated
 * the (IPv6 addresses * IPv4 addresses * ports). This can produce
 * a 128-bit number (larger, actually).
 */
int128_t targetip_range(TargetIP *targetip);

/**
 * Remove everything in "targets" that's listed in the "exclude"
 * list. The reason for this is that we'll have a single policy
 * file of those address ranges which we are forbidden to scan.
 * Then, each time we run a scan with different targets, we
 * apply this policy file.
 */
void targetip_apply_excludes(TargetIP *targets, TargetIP *exclude);

/**
 * The last step after processing the configuration, setting up the
 * state to be used for scanning. This sorts the address, removes
 * duplicates, and creates an optimized 'picker' system to easily
 * find an address given an index, or find an index given an address.
 */
void targetip_optimize(TargetIP *targets);

/**
 * This selects an IP+port combination given an index whose value
 * is [0..range], where 'range' is the value returned by the function
 * `targetip_range()`. Since the optimization step (`targetip_optimized()`)
 * sorted all addresses/ports, a monotonically increasing index will
 * list everything in sorted order. The intent, however, is to use the
 * "blackrock" algorithm to randomize the index before calling this function.
 *
 * It is this function, plus the 'blackrock' randomization algorithm, that
 * is at the heart of Xconf.
 */
void targetip_pick(const TargetIP *targetip, uint64_t index, ipaddress *addr,
                   unsigned *port);

bool targetip_has_ip(const TargetIP *targetip, ipaddress ip);

bool targetip_has_port(const TargetIP *targetip, unsigned port);

int targetip_add_target_string(TargetIP *targetip, const char *string);

/**
 * Parse the string contain port specifier.
 */
int targetip_add_port_string(TargetIP *targetip, const char *string,
                             unsigned proto);

/**
 * Indicates whether there are IPv4 targets. If so, we'll have to
 * initialize the IPv4 portion of the stack.
 * @return true if there are IPv4 targets to be scanned, false
 * otherwise
 */
bool targetip_has_ipv4_targets(const TargetIP *targetip);
bool targetip_has_target_ports(const TargetIP *targetip);

/**
 * Indicates whether there are IPv6 targets. If so, we'll have to
 * initialize the IPv6 portion of the stack.
 * @return true if there are IPv6 targets to be scanned, false
 * otherwise
 */
bool targetip_has_ipv6_targets(const TargetIP *targetip);

int targetip_selftest();

#endif

#include "target.h"

const char *ip_proto_to_string(unsigned ip_proto) {
    switch (ip_proto) {
        case IP_PROTO_HOPOPT:
            return "HOPOPT";
        case IP_PROTO_ICMP:
            return "ICMP";
        case IP_PROTO_IGMP:
            return "IGMP";
        case IP_PROTO_GGP:
            return "GGP";
        case IP_PROTO_IPv4:
            return "IPv4";
        case IP_PROTO_TCP:
            return "TCP";
        case IP_PROTO_EGP:
            return "EGP";
        case IP_PROTO_IGP:
            return "IGP";
        case IP_PROTO_UDP:
            return "UDP";
        case IP_PROTO_IPv6:
            return "IPv6";
        case IP_PROTO_IPv6_Route:
            return "IPv6_Route";
        case IP_PROTO_IPv6_Frag:
            return "IPv6_Frag";
        case IP_PROTO_IDRP:
            return "IDRP";
        case IP_PROTO_GRE:
            return "GRE";
        case IP_PROTO_Min_IPv4:
            return "Min_IPv4";
        case IP_PROTO_IPv6_ICMP:
            return "IPv6_ICMP";
        case IP_PROTO_IPv6_NoNxt:
            return "IPv6_NoNxt";
        case IP_PROTO_IPv6_Opts:
            return "IPv6_Opts";
        case IP_PROTO_OSPFIGP:
            return "OSPFIGP";
        case IP_PROTO_ETHERIP:
            return "ETHERIP";
        case IP_PROTO_L2TP:
            return "L2TP";
        case IP_PROTO_ISIS_over_IPv4:
            return "ISIS_over_IPv4";
        case IP_PROTO_SCTP:
            return "SCTP";
        case IP_PROTO_MPLS_in_IP:
            return "MPLS_in_IP";

        default:
            return "Other";
    }
}
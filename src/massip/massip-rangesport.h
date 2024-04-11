#ifndef MASSIP_RANGESPORT_H
#define MASSIP_RANGESPORT_H

struct RangeList;

#define MASSIP_PORT_SPEC 65535

/*
 * Ports are 16-bit numbers ([0..65535], but different
 * transports (TCP, UDP, SCTP, Other IP protocol num) are distinct port ranges.
 * Thus, we instead of three 64k and one 0xFF ranges we could instead treat
 * this internally together.
 * We can expand this range to include other
 * things we scan for, such as ICMP pings or ARP requests.
 */
enum Proto_Port_range{
    Range_TCP                = (MASSIP_PORT_SPEC+1)*0,
    Range_TCP_last           = (MASSIP_PORT_SPEC+1)*0 + MASSIP_PORT_SPEC,
    Range_UDP                = (MASSIP_PORT_SPEC+1)*1,
    Range_UDP_last           = (MASSIP_PORT_SPEC+1)*1 + MASSIP_PORT_SPEC,
    Range_SCTP               = (MASSIP_PORT_SPEC+1)*2,
    Range_SCTP_last          = (MASSIP_PORT_SPEC+1)*2 + MASSIP_PORT_SPEC,
    Range_Oproto             = (MASSIP_PORT_SPEC+1)*3,
    Range_Oproto_last        = (MASSIP_PORT_SPEC+1)*3 + MASSIP_PORT_SPEC,
};

enum PortProto {
    Port_TCP = 1,
    Port_UDP,
    Port_SCTP,
    Port_Oproto,
};

void
rangelist_add_range_tcp(struct RangeList *targets, unsigned begin, unsigned end);

void
rangelist_add_range_udp(struct RangeList *targets, unsigned begin, unsigned end);

/**
 * Given a string like "80,8080,20-25,U:161", parse it into a structure
 * containing a list of port ranges.
 *
 * @param ports
 *      The array of port ranges that's produced by this parsing function.
 *      This structure will be used by the transmit thread when sending
 *      probes to a target IP address.
 * @param string
 *      A string from either the command-line or configuration file
 *      in the nmap "ports" format.
 * @param is_error
 *      Set to zero is no error occurred while parsing the string, or
 *      set to a non-zero value if an error was found.
 * @return
 *      the pointer in the string where the parsing ended, so that additional
 *      things can be contained in the string, such as comments
 */
const char *
rangelist_parse_ports(struct RangeList *ports,
    const char *string,
    unsigned *is_error,
    unsigned proto_offset);

/**
 * transfer port from range format to real port
 * and get what protocol this port belong to.
 * @param raw_port port Proto Port range format
 * @return enum PortProto or zero if invalid.
*/
enum PortProto
get_actual_proto_port(unsigned *raw_port);

#endif

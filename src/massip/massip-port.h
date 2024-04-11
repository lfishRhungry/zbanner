#ifndef MASSIP_PORT_H
#define MASSIP_PORT_H

#define MASSIP_PORT_RANGE 65535

/*
 * Ports are 16-bit numbers ([0..65535], but different
 * transports (TCP, UDP, SCTP, Other IP protocol num) are distinct port ranges.
 * Thus, we instead of three 64k and one 0xFF ranges we could instead treat
 * this internally together.
 * We can expand this range to include other
 * things we scan for, such as ICMP pings or ARP requests.
 */
enum Proto_Port_range{
    Range_TCP                = (MASSIP_PORT_RANGE+1)*0,
    Range_TCP_last           = (MASSIP_PORT_RANGE+1)*0 + MASSIP_PORT_RANGE,
    Range_UDP                = (MASSIP_PORT_RANGE+1)*1,
    Range_UDP_last           = (MASSIP_PORT_RANGE+1)*1 + MASSIP_PORT_RANGE,
    Range_SCTP               = (MASSIP_PORT_RANGE+1)*2,
    Range_SCTP_last          = (MASSIP_PORT_RANGE+1)*2 + MASSIP_PORT_RANGE,
    Range_Oproto             = (MASSIP_PORT_RANGE+1)*3,
    Range_Oproto_last        = (MASSIP_PORT_RANGE+1)*3 + MASSIP_PORT_RANGE,
};

enum PortProto {
    Port_TCP = 1,
    Port_UDP,
    Port_SCTP,
    Port_Oproto,
};

/**
 * transfer port from range format to real port
 * and get what protocol this port belong to.
 * @param raw_port port Proto Port range format
 * @return enum PortProto or zero if invalid.
*/
enum PortProto
get_actual_proto_port(unsigned *raw_port);

#endif

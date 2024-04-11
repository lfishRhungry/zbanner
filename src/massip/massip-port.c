#include "massip-port.h"

enum PortProto
get_actual_proto_port(unsigned *raw_port)
{
    if (*raw_port <= Range_TCP_last)
        return Port_TCP;
    else if (*raw_port <= Range_UDP_last) {
        *raw_port &= 0xFFFF;
        return Port_UDP;
    } else if (*raw_port <= Range_SCTP_last) {
        *raw_port &= 0xFFFF;
        return Port_SCTP;
    } else if (*raw_port <= Range_Oproto_last) {
        *raw_port &= 0xFFFF;
        return Port_Oproto;
    } else {
        return 0;
    }
}
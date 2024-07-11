#include "stack-src.h"

bool is_myself(const StackSrc *src, ipaddress ip, unsigned port) {
    return is_my_ip(src, ip) && is_my_port(src, port);
}

bool is_my_ip(const StackSrc *src, ipaddress ip) {
    switch (ip.version) {
        case 4:
            return src->ipv4.first <= ip.ipv4 && ip.ipv4 <= src->ipv4.last;
        case 6:
            return src->ipv6.first.hi == ip.ipv6.hi &&
                   src->ipv6.first.lo <= ip.ipv6.lo &&
                   ip.ipv6.lo <= src->ipv6.last.lo;
        default:
            return false;
    }
}

bool is_my_port(const StackSrc *src, unsigned port) {
    return src->port.first <= port && port <= src->port.last;
}

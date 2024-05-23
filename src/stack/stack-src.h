#ifndef STACK_SOURCE_H
#define STACK_SOURCE_H
#include "../massip/massip-addr.h"

/**
 * These the source IP addresses that we'll be spoofing. IP addresses
 * and port numbers come from this list.
 */
struct stack_src_t
{
    struct {
        unsigned first;
        unsigned last;
        unsigned range;
    } ipv4;
    struct {
        unsigned first;
        unsigned last;
        unsigned range;
    } port;

    struct {
        ipv6address first;
        ipv6address last;
        uint64_t    range;
    } ipv6;
};

bool is_myself(const struct stack_src_t *src, ipaddress ip, unsigned port);
bool is_my_ip(const struct stack_src_t *src, ipaddress ip);
bool is_my_port(const struct stack_src_t *src, unsigned port);



#endif

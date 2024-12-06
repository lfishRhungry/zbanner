#ifndef STACK_SOURCE_H
#define STACK_SOURCE_H

#include "../target/target-ipaddress.h"

/**
 * These the source IP addresses that we'll be spoofing. IP addresses
 * and port numbers come from this list.
 */
typedef struct StackOfSource {
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
} StackSrc;

bool is_myself(const StackSrc *src, ipaddress ip, unsigned port);
bool is_my_ip(const StackSrc *src, ipaddress ip);
bool is_my_port(const StackSrc *src, unsigned port);

#endif

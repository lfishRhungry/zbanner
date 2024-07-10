/*
    Born from Masscan
    Modified by lishRhungry 2024
*/
#ifndef TARGET_COOKIE_H
#define TARGET_COOKIE_H
#include <stdint.h>
#include "target-addr.h"

/**
 * Create a hash of the src/dst IP/port combination. This allows us to match
 * incoming responses with their original requests
 */
uint64_t
get_cookie_ipv4(unsigned ip_them, unsigned port_them,
    unsigned ip_me, unsigned port_me,
    uint64_t entropy);

uint64_t
get_cookie(ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    uint64_t entropy);

uint64_t
get_cookie_ipv6(ipv6address ip_them, unsigned port_them,
    ipv6address ip_me, unsigned port_me,
    uint64_t entropy);


/**
 * Called on startup to set a secret key
 */
uint64_t get_one_entropy(void);


#endif

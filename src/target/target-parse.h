/*
    Born from Masscan
    Modified by lishRhungry 2024
*/
/*
    target-parse

    This module parses IPv4 and IPv6 addresses.

    It's not a typical parser. It's optimized around parsing large
    files containing millions of addresses and ranges using a 
    "state-machine parser".
*/
#ifndef TARGET_PARSE_H
#define TARGET_PARSE_H
#include "target-addr.h"

typedef struct Target_IPs_Ports TargetIP;
struct Range;
struct Range6;

/**
 * Parse a file, extracting all the IPv4 and IPv6 addresses and ranges.
 * This is optimized for speed, handling millions of entries in under
 * a second. This is especially tuned for IPv6 addresses, as while IPv4
 * scanning is mostly done with target rnages, IPv6 scanning is mostly
 * done with huge lists of target addresses.
 * @param filename
 *      The name of the file that we'll open, parse, and close.
 * @param targets_ipv4
 *      The list of IPv4 targets that we append any IPv4 addresses to.
 * @param targets_ipv6
 *      The list of IPv6 targets that we append any IPv6 addresses/ranges to.
 * @return 
        0 on success, any other number on failure.
 */
int
targetip_parse_file(TargetIP *targetip, const char *filename);


enum RangeParseResult {
    Bad_Address,
    Ipv4_Address=4,
    Ipv6_Address=6,
};

/**
 * Parse the next IPv4/IPv6 range from a string. This is called
 * when parsing strings from the command-line.
 */
enum RangeParseResult
targetip_parse_range(const char *line, size_t *inout_offset, size_t max, struct Range *ipv4, struct Range6 *ipv6);



/**
 * Parse a single IPv6 address. This is called when working with
 * the operating system stack, when querying addresses from
 * the local network adapters.
 */
ipv6address_t
targetip_parse_ipv6(const char *buf);

ipv4address_t
targetip_parse_ipv4(const char *buf);

/**
 * got version 0 if failed
*/
ipaddress
targetip_parse_ip(const char *line);

int targetip_parse_selftest();

#endif


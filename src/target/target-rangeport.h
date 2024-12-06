/**
 * Born and updated from Masscan
 * Modified and Created by sharkocha 2024
 */
#ifndef TARGET_RANGE_PORT_H
#define TARGET_RANGE_PORT_H

#include <stdint.h>
#include <stdio.h>

struct RangeList;

void rangelist_add_range_tcp(struct RangeList *targets, unsigned begin,
                             unsigned end);

void rangelist_add_range_udp(struct RangeList *targets, unsigned begin,
                             unsigned end);

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
const char *rangelist_parse_ports(struct RangeList *ports, const char *string,
                                  unsigned *is_error, unsigned proto_offset);

/**
 * print ports in a line of `port = 80-81,82-88,U:85-99...\n` format
 */
void rangeport_println(const struct RangeList *ports, FILE *fp);

/**
 * print just ports in `80-81,82-88,U:85-99...` format
 * @param default_ipproto won't be printed with prefix like U:, T: or S:
 */
void rangeport_print(const struct RangeList *ports, FILE *fp,
                     unsigned default_ipproto);

/**
 * transfer port from range format to real port
 * and get what protocol this port belong to.
 * @param raw_port port Proto Port range format
 * @return ip proto number
 */
uint16_t get_actual_proto_port(unsigned *raw_port);

/**
 * transfer port from real port and ip proto to range format
 * @return port in range format
 */
unsigned get_complex_port(uint16_t port, unsigned ip_proto);

int rangesport_selftest();

#endif

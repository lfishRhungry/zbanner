#include "target-set.h"
#include "target-rangeport.h"
#include "target-rangelist.h"

#include "../util-out/logger.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/** Use this when adding TCP ports, to avoid the comoplication of how
 * ports are stored */
void rangelist_add_range_tcp(struct RangeList *targets, unsigned begin,
                             unsigned end) {
    rangelist_add_range(targets, Range_TCP + begin, Range_TCP + end);
}

/** Use this when adding UDP ports, to avoid the comoplication of how
 * ports are stored */
void rangelist_add_range_udp(struct RangeList *targets, unsigned begin,
                             unsigned end) {
    rangelist_add_range(targets, Range_UDP + begin, Range_UDP + end);
}

/***************************************************************************
 * This returns a character pointer where parsing ends so that it can
 * handle multiple stuff on the same line
 ***************************************************************************/
const char *rangelist_parse_ports(struct RangeList *ports, const char *string,
                                  unsigned *is_error, unsigned proto_offset) {
    char    *p   = (char *)string;
    unsigned tmp = 0;

    if (is_error == NULL)
        is_error = &tmp;

    *is_error = 0;
    while (*p) {
        unsigned port;
        unsigned end;

        /* skip whitespace */
        while (*p && isspace(*p & 0xFF))
            p++;

        /* end at comment */
        if (*p == 0 || *p == '#')
            break;

        /* special processing. Nmap allows ports to be prefixed with a
         * characters to clarify TCP, UDP, or SCTP */
        if (isalpha(*p & 0xFF) && p[1] == ':') {
            switch (*p) {
                case 'T':
                case 't':
                    proto_offset = 0;
                    break;
                case 'U':
                case 'u':
                    proto_offset = Range_UDP;
                    break;
                case 'S':
                case 's':
                    proto_offset = Range_SCTP;
                    break;
                case 'O':
                case 'o':
                    proto_offset = Range_Oproto;
                    break;
                default:
                    LOG(LEVEL_ERROR, "bad port character = %c\n", p[0]);
                    *is_error = 1;
                    return p;
            }
            p += 2;
        }

        /*
         * Get the start of the range.
         */
        if (p[0] == '-') {
            /* nmap style port range spec meaning starting with 0 */
            port = 1;
        } else if (isdigit(p[0] & 0xFF)) {
            port = (unsigned)strtoul(p, &p, 0);
        } else {
            break;
        }

        /*
         * Get the end of the range
         */
        if (*p == '-') {
            p++;
            if (!isdigit(*p)) {
                /* nmap style range spec meaning end with 65535 */
                end = TARGET_PORT_SPEC;
            } else {
                end = (unsigned)strtoul(p, &p, 0);
            }
        } else
            end = port;

        /* Check for out-of-range */
        if (port > TARGET_PORT_SPEC || end > TARGET_PORT_SPEC || end < port) {
            LOG(LEVEL_ERROR, "bad port range: %s\n", string);
            *is_error = 2;
            return p;
        }

        /* Add to our list */
        rangelist_add_range(ports, port + proto_offset, end + proto_offset);

        /* skip trailing whitespace */
        while (*p && isspace(*p & 0xFF))
            p++;

        /* Now get the next port/range if there is one */
        if (*p != ',')
            break;
        p++;
    }

    return p;
}

uint8_t get_actual_proto_port(unsigned *raw_port) {
    if (*raw_port <= Range_TCP_last)
        return IP_PROTO_TCP;
    else if (*raw_port <= Range_UDP_last) {
        *raw_port &= 0xFFFF;
        return IP_PROTO_UDP;
    } else if (*raw_port <= Range_SCTP_last) {
        *raw_port &= 0xFFFF;
        return IP_PROTO_SCTP;
    } else if (*raw_port <= Range_Oproto_last) {
        *raw_port &= 0xFFFF;
        return IP_PROTO_Other;
    } else {
        return IP_PROTO_Other;
    }
}

int rangesport_selftest() {
    TargetSet targets = {.ipv4 = {0}, .ipv6 = {0}, .ports = {0}};

    unsigned err;
    int      line;

    /*Positive Samples*/
    line = __LINE__;
    err  = 0;
    rangelist_parse_ports(&targets.ports, "8080,-80,100-120", &err, 0);
    if (err)
        goto fail;

    line = __LINE__;
    err  = 0;
    rangelist_parse_ports(&targets.ports, "t:120,u:33-66", &err, 0);
    if (err)
        goto fail;

    line = __LINE__;
    err  = 0;
    rangelist_parse_ports(&targets.ports, "22,s:8080-9090,o:9090-10000", &err,
                          0);
    if (err)
        goto fail;

    return 0;

fail:
    LOG(LEVEL_ERROR, "rangesport: test fail, line=%d\n", line);
    return 1;
}
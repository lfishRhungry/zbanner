#ifndef TEMPL_UDP_H
#define TEMPL_UDP_H

#include <stdio.h>

#include "templ-pkt.h"
#include "../util-misc/cross.h"
#include "../target/target-addr.h"

/**
 * @param ttl use default value in packet template if set to zero.
 */
size_t
udp_create_by_template(
    TmplPkt *tmpl,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned ttl,
    unsigned char *payload, size_t payload_length,
    unsigned char *px, size_t sizeof_px);

/**
 * @param ttl use default value in packet template if set to zero.
 */
size_t
udp_create_packet(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned ttl,
    unsigned char *payload, size_t payload_length,
    unsigned char *px, size_t sizeof_px);

#endif
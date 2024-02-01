#ifndef TEMPL_UDP_H
#define TEMPL_UDP_H

#include <stdio.h>

#include "templ-pkt.h"
#include "../util/bool.h" /* <stdbool.h> */
#include "../massip/massip-addr.h"

size_t
udp_create_by_template(
    struct TemplatePacket *tmpl,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned char *payload, size_t payload_length,
    unsigned char *px, size_t sizeof_px);

#endif
#ifndef TEMPL_SCTP_H
#define TEMPL_SCTP_H

#include <stdio.h>

#include "templ-pkt.h"
#include "../target/target-ipaddress.h"

#define SCTP_CHUNK_TYPE_DATA              0
#define SCTP_CHUNK_TYPE_INIT              1
#define SCTP_CHUNK_TYPE_INIT_ACK          2
#define SCTP_CHUNK_TYPE_SACK              3
#define SCTP_CHUNK_TYPE_HEARTBEAT         4
#define SCTP_CHUNK_TYPE_HEARTBEAT_ACK     5
#define SCTP_CHUNK_TYPE_ABORT             6
#define SCTP_CHUNK_TYPE_SHUTDOWN          7
#define SCTP_CHUNK_TYPE_SHUTDOWN_ACK      8
#define SCTP_CHUNK_TYPE_ERROR             9
#define SCTP_CHUNK_TYPE_COOKIE_ECHO       10
#define SCTP_CHUNK_TYPE_COOKIE_ACK        11
#define SCTP_CHUNK_TYPE_ECNE              12
#define SCTP_CHUNK_TYPE_CWR               13
#define SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE 14

#define SCTP_VERI_TAG(px, transport_offset)                                    \
    ((px)[(transport_offset) + 4] << 24 | (px)[(transport_offset) + 5] << 16 | \
     (px)[(transport_offset) + 6] << 8 | (px)[(transport_offset) + 7])
#define SCTP_CHUNK_TYPE(px, transport_offset) ((px)[(transport_offset) + 12])
#define SCTP_IS_CHUNK_TYPE(px, transport_offset, type)                         \
    ((SCTP_CHUNK_TYPE((px), (transport_offset))) == (type))

/**
 * @param ttl use default value in packet template if set to zero.
 */
size_t sctp_create_by_template(const TmplPkt *tmpl, ipaddress ip_them,
                               unsigned port_them, ipaddress ip_me,
                               unsigned port_me, unsigned init_tag,
                               unsigned ttl, unsigned char *px,
                               size_t sizeof_px);

/**
 * @param ttl use default value in packet template if set to zero.
 */
size_t sctp_create_packet(ipaddress ip_them, unsigned port_them,
                          ipaddress ip_me, unsigned port_me, unsigned init_tag,
                          unsigned ttl, unsigned char *px, size_t sizeof_px);

#endif
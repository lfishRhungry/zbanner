#ifndef TEMPL_SCTP_H
#define TEMPL_SCTP_H

#include <stdio.h>

#include "templ-pkt.h"
#include "../util-misc/cross.h"
#include "../massip/massip-addr.h"

#define SCTP_CHUNK_TYPE_DATA                0
#define SCTP_CHUNK_TYPE_INIT                1
#define SCTP_CHUNK_TYPE_INIT_ACK            2
#define SCTP_CHUNK_TYPE_SACK                3
#define SCTP_CHUNK_TYPE_HEARTBEAT           4
#define SCTP_CHUNK_TYPE_HEARTBEAT_ACK       5
#define SCTP_CHUNK_TYPE_ABORT               6
#define SCTP_CHUNK_TYPE_SHUTDOWN            7
#define SCTP_CHUNK_TYPE_SHUTDOWN_ACK        8
#define SCTP_CHUNK_TYPE_ERROR               9
#define SCTP_CHUNK_TYPE_COOKIE_ECHO        10
#define SCTP_CHUNK_TYPE_COOKIE_ACK         11
#define SCTP_CHUNK_TYPE_ECNE               12
#define SCTP_CHUNK_TYPE_CWR                13
#define SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE  14

#define SCTP_VERI_TAG(px,i) (px[i+4]<<24|px[i+5]<<16|px[i+6]<<8|px[i+7])
#define SCTP_CHUNK_TYPE(px,i) (px[(i)+12])
#define SCTP_IS_CHUNK_TYPE(px,i,type) ((SCTP_CHUNK_TYPE((px),(i))) == (type))

size_t
sctp_create_by_template(
    struct TemplatePacket *tmpl,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned init_tag,
    unsigned char *px, size_t sizeof_px);

size_t
sctp_create_packet(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned init_tag,
    unsigned char *px, size_t sizeof_px);

#endif
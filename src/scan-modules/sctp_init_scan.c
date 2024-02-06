#include <stdlib.h>

#include "sctp_init_scan.h"
#include "../cookie.h"
#include "../templ/templ-sctp.h"
#include "../util/mas-safefunc.h"
#include "../util/mas-malloc.h"

extern struct ScanModule SctpInitScan; /*for internal x-ref*/

static int
sctpinit_make_packet(
    unsigned cur_proto,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    uint64_t entropy, unsigned index,
    unsigned char *px, unsigned sizeof_px, size_t *r_length)
{
    /*we just handle tcp target*/
    if (cur_proto != Proto_SCTP) {
        *r_length = 0;
        return 0;
    }

    unsigned cookie = get_cookie(ip_them, port_them, ip_me, port_me, entropy);

    *r_length = sctp_create_packet(
        ip_them, port_them, ip_me, port_me,
        cookie, px, sizeof_px);
    
    /*no need do send again in this moment*/
    return 0;
}

static int
sctpinit_filter_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned is_myip, unsigned is_myport)
{
    /*record tcp packet to our source port*/
    if (parsed->found == FOUND_SCTP && is_myip && is_myport)
        return 1;
    
    return 0;
}

static int
sctpinit_validate_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px)
{
    /*packet is too short*/
    if (parsed->transport_offset + 16 > sizeof_px)
        return 0;

    ipaddress ip_me    = parsed->dst_ip;
    ipaddress ip_them  = parsed->src_ip;
    unsigned port_me   = parsed->port_dst;
    unsigned port_them = parsed->port_src;
    unsigned veri_tag  = SCTP_VERI_TAG(px, parsed->transport_offset);
    unsigned cookie    = get_cookie(ip_them, port_them, ip_me, port_me, entropy);

    if (cookie != veri_tag)
        return 0;
    
    if (SCTP_IS_CHUNK_TYPE(px, parsed->transport_offset, SCTP_CHUNK_TYPE_INIT_ACK))
        return 1;
    
    if (SCTP_IS_CHUNK_TYPE(px, parsed->transport_offset, SCTP_CHUNK_TYPE_ABORT))
        return 1;

    return 0;
}

static int
sctpinit_dedup_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    ipaddress *ip_them, unsigned *port_them,
    ipaddress *ip_me, unsigned *port_me, unsigned *type)
{
    //just one type for tcpsyn and use default ip:port
    return 1;
}

static int
sctpinit_handle_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned *successed,
    char *classification, unsigned cls_length,
    char *report, unsigned rpt_length)
{
    *successed = 0;

    if (SCTP_IS_CHUNK_TYPE(px, parsed->transport_offset, SCTP_CHUNK_TYPE_INIT_ACK)) {
        *successed = 1;
        safe_strcpy(classification, cls_length, "init-ack");
    } else if (SCTP_IS_CHUNK_TYPE(px, parsed->transport_offset, SCTP_CHUNK_TYPE_ABORT)) {
        safe_strcpy(classification, cls_length, "abort");
    }

    /*no need to response*/
    return 0;
}

struct ScanModule SctpInitScan = {
    .name = "sctpinit",
    .desc =
        "SctpInitScan sends an SCTP INIT packet(chunk) to target port. Expect an "
        "INIT ACK response to believe the port is open or an ABORT for closed in "
        "SCTP protocol.\n",

    .global_init_cb = NULL,
    .rx_thread_init_cb = NULL,
    .tx_thread_init_cb = NULL,

    .make_packet_cb = sctpinit_make_packet,

    .filter_packet_cb = sctpinit_filter_packet,
    .validate_packet_cb = sctpinit_validate_packet,
    .dedup_packet_cb = sctpinit_dedup_packet,
    .handle_packet_cb = sctpinit_handle_packet,
    .response_packet_cb = NULL,

    .close_cb = NULL,
};
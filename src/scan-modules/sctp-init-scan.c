#include <stdlib.h>

#include "scan-modules.h"
#include "../cookie.h"
#include "../templ/templ-sctp.h"
#include "../util/mas-safefunc.h"
#include "../util/mas-malloc.h"

extern struct ScanModule SctpInitScan; /*for internal x-ref*/

static int
sctpinit_transmit(
    uint64_t entropy,
    struct ScanTarget *target,
    struct ScanTimeoutEvent *event,
    unsigned char *px, size_t *len)
{
    /*we just handle tcp target*/
    if (target->proto != Proto_SCTP)
        return 0;

    unsigned cookie = get_cookie(target->ip_them, target->port_them,
        target->ip_me, target->port_me, entropy);

    *len = sctp_create_packet(target->ip_them, target->port_them,
        target->ip_me, target->port_me,
        cookie, px, PKT_BUF_LEN);

    return 0;
}

static void
sctpinit_validate(
    uint64_t entropy,
    struct Received *recved,
    struct PreHandle *pre)
{
    /*record all sctp to me*/
    if (recved->parsed.found == FOUND_SCTP
        && recved->is_myip
        && recved->is_myport)
        pre->go_record = 1;
    else return;

    /*packet is too short*/
    if (recved->parsed.transport_offset + 16 > recved->length)
        return;

    ipaddress ip_them  = recved->parsed.src_ip;
    ipaddress ip_me    = recved->parsed.dst_ip;
    unsigned port_them = recved->parsed.port_src;
    unsigned port_me   = recved->parsed.port_dst;

    unsigned veri_tag  = SCTP_VERI_TAG(recved->packet, recved->parsed.transport_offset);
    unsigned cookie    = get_cookie(ip_them, port_them, ip_me, port_me, entropy);

    if (cookie != veri_tag)
        return;
    
    if (SCTP_IS_CHUNK_TYPE(recved->packet, recved->parsed.transport_offset,
        SCTP_CHUNK_TYPE_INIT_ACK)) {
        pre->go_dedup = 1;
    } else if (SCTP_IS_CHUNK_TYPE(recved->packet, recved->parsed.transport_offset,
        SCTP_CHUNK_TYPE_ABORT)) {
        pre->go_dedup = 1;
    }
}

static void
sctpinit_handle(
    uint64_t entropy,
    struct Received *recved,
    struct OutputItem *item,
    struct stack_t *stack,
    struct FHandler *handler)
{
    if (SCTP_IS_CHUNK_TYPE(recved->packet, recved->parsed.transport_offset,
        SCTP_CHUNK_TYPE_INIT_ACK)) {
        item->is_success = 1;
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "init-ack");
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "open");
    } else if (SCTP_IS_CHUNK_TYPE(recved->packet, recved->parsed.transport_offset,
        SCTP_CHUNK_TYPE_ABORT)) {
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "abort");
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "closed");
    }
}

struct ScanModule SctpInitScan = {
    .name = "sctpinit",
    .required_probe_type = 0,
    .support_timeout = 0,
    .bpf_filter = "sctp && (sctp[12]==2 || sctp[12]==6)", /*sctp init or init ack*/
    .desc =
        "SctpInitScan sends an SCTP INIT packet(chunk) to target port. Expect an "
        "INIT ACK response to believe the port is open or an ABORT for closed in "
        "SCTP protocol.\n",

    .global_init_cb          = &scan_init_nothing,
    .transmit_cb             = &sctpinit_transmit,
    .validate_cb             = &sctpinit_validate,
    .handle_cb               = &sctpinit_handle,
    .timeout_cb              = &scan_no_timeout,
    .close_cb                = &scan_close_nothing,
};
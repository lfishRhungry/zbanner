#include <stdlib.h>

#include "scan-modules.h"
#include "../cookie.h"
#include "../templ/templ-tcp.h"
#include "../util/safe-string.h"
#include "../util/fine-malloc.h"

extern struct ScanModule TcpSynScan; /*for internal x-ref*/

static int
tcpsyn_transmit(
    uint64_t entropy,
    struct ScanTarget *target,
    struct ScanTimeoutEvent *event,
    unsigned char *px, size_t *len)
{
    /*we just handle tcp target*/
    if (target->proto != Proto_TCP)
        return 0;

    unsigned cookie = get_cookie(target->ip_them, target->port_them,
        target->ip_me, target->port_me, entropy);

    *len = tcp_create_packet(
        target->ip_them, target->port_them, target->ip_me, target->port_me,
        cookie, 0, TCP_FLAG_SYN, NULL, 0, px, PKT_BUF_LEN);
    
    /*add timeout*/
    event->need_timeout = 1;

    return 0;
}

static void
tcpsyn_validate(
    uint64_t entropy,
    struct Received *recved,
    struct PreHandle *pre)
{
    /*record tcp packet to our source port*/
    if (recved->parsed.found == FOUND_TCP
        && recved->is_myip
        && recved->is_myport)
        pre->go_record = 1;
    else return;

    ipaddress ip_them  = recved->parsed.src_ip;
    ipaddress ip_me    = recved->parsed.dst_ip;
    unsigned port_them = recved->parsed.port_src;
    unsigned port_me   = recved->parsed.port_dst;
    unsigned seqno_me  = TCP_ACKNO(recved->packet, recved->parsed.transport_offset);
    unsigned cookie    = get_cookie(ip_them, port_them, ip_me, port_me, entropy);

    /*SYNACK*/
    if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
        TCP_FLAG_SYN|TCP_FLAG_ACK)) {
        if (cookie == seqno_me - 1) {
            pre->go_dedup = 1;
        }
    }
    /*RST*/
    else if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
        TCP_FLAG_RST)) {
        /*NOTE: diff from SYNACK*/
        if (cookie == seqno_me - 1 || cookie == seqno_me) {
            pre->go_dedup = 1;
        }
    }
}

static void
tcpsyn_handle(
    unsigned th_idx,
    uint64_t entropy,
    struct Received *recved,
    struct OutputItem *item,
    struct stack_t *stack,
    struct FHandler *handler)
{

    /*SYNACK*/
    if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
        TCP_FLAG_SYN|TCP_FLAG_ACK)) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "syn-ack");

        uint16_t win_them =
            TCP_WIN(recved->packet, recved->parsed.transport_offset);
        if (win_them == 0) {
            safe_strcpy(item->classification, OUTPUT_CLS_LEN, "zerowin");
        } else {
            safe_strcpy(item->classification, OUTPUT_CLS_LEN, "open");
        }
    }
    /*RST*/
    else {
        item->level = Output_FAILURE;
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "rst");
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "closed");
    }
}

void tcpsyn_timeout(
    uint64_t entropy,
    struct ScanTimeoutEvent *event,
    struct OutputItem *item,
    struct stack_t *stack,
    struct FHandler *handler)
{
    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "closed");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "timeout");
}

struct ScanModule TcpSynScan = {
    .name                = "tcp-syn",
    .required_probe_type = 0,
    .support_timeout     = 1,
    .params              = NULL,
    .bpf_filter          = "tcp && (tcp[13] & 4 != 0 || tcp[13] == 18)", /*tcp rst or syn-ack*/
    .desc =
        "TcpSynScan sends a TCP SYN packet to target port. Expect a SYNACK "
        "response to believe the port is open or an RST for closed in TCP protocol.\n"
        "TcpSynScan is the default ScanModule.",

    .global_init_cb           = &scan_global_init_nothing,
    .transmit_cb              = &tcpsyn_transmit,
    .validate_cb              = &tcpsyn_validate,
    .handle_cb                = &tcpsyn_handle,
    .timeout_cb               = &tcpsyn_timeout,
    .poll_cb                  = &scan_poll_nothing,
    .close_cb                 = &scan_close_nothing,
};
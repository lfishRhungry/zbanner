#include <stdlib.h>

#include "scan-modules.h"
#include "../cookie.h"
#include "../templ/templ-tcp.h"
#include "../util/mas-safefunc.h"
#include "../util/mas-malloc.h"

extern struct ScanModule TcpSynScan; /*for internal x-ref*/

static void
tcpsyn_transmit(
    unsigned cur_proto, uint64_t entropy,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    sendp_in_tx sendp, void * sendp_params)
{
    /*we just handle tcp target*/
    if (cur_proto != Proto_TCP)
        return;

    unsigned cookie = get_cookie(ip_them, port_them, ip_me, port_me, entropy);

    unsigned char px[2048];
    size_t length = tcp_create_packet(
        ip_them, port_them, ip_me, port_me,
        cookie, 0, TCP_FLAG_SYN,
        NULL, 0, px, 2048);

    sendp(sendp_params, px, length);
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
    uint64_t entropy,
    struct Received *recved,
    struct OutputItem *item,
    struct stack_t *stack)
{

    /*SYNACK*/
    if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
        TCP_FLAG_SYN|TCP_FLAG_ACK)) {
        item->is_success = 1;
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
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "rst");
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "closed");
    }
}

struct ScanModule TcpSynScan = {
    .name = "tcpsyn",
    .required_probe_type = 0,
    .desc =
        "TcpSynScan sends a TCP SYN packet to target port. Expect a SYNACK "
        "response to believe the port is open or an RST for closed in TCP protocol.\n"
        "TcpSynScan is the default ScanModule.\n",

    .global_init_cb           = &scan_init_nothing,
    .transmit_cb              = &tcpsyn_transmit,
    .validate_cb              = &tcpsyn_validate,
    .handle_cb                = &tcpsyn_handle,
    .close_cb                 = &scan_close_nothing,
};
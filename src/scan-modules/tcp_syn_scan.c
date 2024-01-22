#include <stdlib.h>

#include "tcp_syn_scan.h"
#include "../util/mas-safefunc.h"
#include "../util/mas-malloc.h"
#include "../cookie.h"
#include "../util/unusedparm.h"

extern struct ScanModule TcpSynScan; /*for internal x-ref*/

static int
tcpsyn_make_packet(
    struct TemplateSet *tmplset,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    uint64_t entropy, unsigned index,
    unsigned char *px, unsigned sizeof_px, size_t *r_length)
{
    unsigned cookie = get_cookie(ip_them, port_them, ip_me, port_me, entropy);

    *r_length = tcp_create_packet(&tmplset->pkts[Proto_TCP],
        ip_them, port_them, ip_me, port_me,
        cookie, 0, TCP_FLAG_SYN,
        NULL, 0, px, sizeof_px);
    
    /*no need do send again in this moment*/
    return SCAN_MODULE_NO_MORE_SEND;
}

static int
tcpsyn_filter_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    const unsigned char *px, unsigned sizeof_px,
    unsigned is_myip, unsigned is_myport)
{
    /*record tcp packet to our source port*/
    if (parsed->found == FOUND_TCP && is_myip && is_myport)
        return SCAN_MODULE_KEEP_PACKET;
    
    return SCAN_MODULE_FILTER_OUT;
}

static int
tcpsyn_validate_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    const unsigned char *px, unsigned sizeof_px)
{
    unsigned seqno_me   = TCP_ACKNO(px, parsed->transport_offset);
    unsigned cookie     = get_cookie(ip_them, port_them, ip_me, port_me, entropy);

    /*SYNACK*/
    if (TCP_HAS_FLAG(px, parsed->transport_offset, TCP_FLAG_SYN|TCP_FLAG_ACK)) {
        if (cookie == seqno_me - 1) {
            return SCAN_MODULE_VALID_PACKET;
        }
    }
    /*RST*/
    else if (TCP_HAS_FLAG(px, parsed->transport_offset, TCP_FLAG_RST)) {
        /*NOTE: diff from SYNACK*/
        if (cookie == seqno_me - 1 || cookie == seqno_me) {
            return SCAN_MODULE_VALID_PACKET;
        }
    }

    return SCAN_MODULE_INVALID_PACKET;
}

static int
tcpsyn_dedup_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    const unsigned char *px, unsigned sizeof_px,
    unsigned *type)
{
    //do not differenciate in type
    *type = SCAN_MODULE_DEFAULT_DEDUP_TYPE;
    return SCAN_MODULE_DO_DEDUP;
}

static int
tcpsyn_handle_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    const unsigned char *px, unsigned sizeof_px,
    unsigned *successed,
    char *classification, unsigned cls_length)
{
    uint16_t win_them   = TCP_WIN(px, parsed->transport_offset);

    *successed = SCAN_MODULE_FAILURE_PACKET;

    /*SYNACK*/
    if (TCP_HAS_FLAG(px, parsed->transport_offset, TCP_FLAG_SYN|TCP_FLAG_ACK)) {
        *successed = SCAN_MODULE_SUCCESS_PACKET;
        if (win_them == 0) {
            safe_strcpy(classification, cls_length, "zerowin");
        } else {
            safe_strcpy(classification, cls_length, "open");
        }
    }
    /*RST*/
    else if (TCP_HAS_FLAG(px, parsed->transport_offset, TCP_FLAG_RST)) {
        safe_strcpy(classification, cls_length, "closed");
    }

    return SCAN_MODULE_NO_RESPONSE;
}

struct ScanModule TcpSynScan = {
    .name = "tcpsyn",
    .description =
        "TcpSynScan sends a TCP SYN packet to target port. Expect a SYNACK "
        "response to believe the port is open or a RST for closed.\n"
        "TcpSynScan is the default ScanModule.\n",

    .global_init_cb = NULL,
    .rx_thread_init_cb = NULL,
    .tx_thread_init_cb = NULL,

    .make_packet_cb = tcpsyn_make_packet,

    .filter_packet_cb = tcpsyn_filter_packet,
    .validate_packet_cb = tcpsyn_validate_packet,
    .dedup_packet_cb = tcpsyn_dedup_packet,
    .handle_packet_cb = tcpsyn_handle_packet,
    .response_packet_cb = NULL,

    .close_cb = NULL,
};
#include <stdlib.h>

#include "tcp_syn_scan.h"
#include "../cookie.h"
#include "../templ/templ-tcp.h"
#include "../util/mas-safefunc.h"
#include "../util/mas-malloc.h"

extern struct ScanModule TcpSynScan; /*for internal x-ref*/

static int
tcpsyn_make_packet(
    unsigned cur_proto,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    uint64_t entropy, unsigned index,
    unsigned char *px, unsigned sizeof_px, size_t *r_length)
{
    /*we just handle tcp target*/
    if (cur_proto != Proto_TCP) {
        *r_length = 0;
        return 0;
    }

    unsigned cookie = get_cookie(ip_them, port_them, ip_me, port_me, entropy);

    *r_length = tcp_create_packet(
        ip_them, port_them, ip_me, port_me,
        cookie, 0, TCP_FLAG_SYN,
        NULL, 0, px, sizeof_px);
    
    /*no need do send again in this moment*/
    return 0;
}

static int
tcpsyn_filter_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned is_myip, unsigned is_myport)
{
    /*record tcp packet to our source port*/
    if (parsed->found == FOUND_TCP && is_myip && is_myport)
        return 1;
    
    return 0;
}

static int
tcpsyn_validate_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px)
{
    ipaddress ip_me = parsed->dst_ip;
    ipaddress ip_them = parsed->src_ip;
    unsigned port_me = parsed->port_dst;
    unsigned port_them = parsed->port_src;
    unsigned seqno_me   = TCP_ACKNO(px, parsed->transport_offset);
    unsigned cookie     = get_cookie(ip_them, port_them, ip_me, port_me, entropy);

    /*SYNACK*/
    if (TCP_HAS_FLAG(px, parsed->transport_offset, TCP_FLAG_SYN|TCP_FLAG_ACK)) {
        if (cookie == seqno_me - 1) {
            return 1;
        }
    }
    /*RST*/
    else if (TCP_HAS_FLAG(px, parsed->transport_offset, TCP_FLAG_RST)) {
        /*NOTE: diff from SYNACK*/
        if (cookie == seqno_me - 1 || cookie == seqno_me) {
            return 1;
        }
    }

    return 0;
}

static int
tcpsyn_dedup_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned *type)
{
    //just one type for tcpsyn
    *type = SCAN_MODULE_DEFAULT_DEDUP_TYPE;
    return 1;
}

static int
tcpsyn_handle_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned *successed,
    char *classification, unsigned cls_length,
    char *report, unsigned rpt_length)
{
    uint16_t win_them   = TCP_WIN(px, parsed->transport_offset);

    *successed = 0;

    /*SYNACK*/
    if (TCP_HAS_FLAG(px, parsed->transport_offset, TCP_FLAG_SYN|TCP_FLAG_ACK)) {
        *successed = 1;
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

    /*no need to response*/
    return 0;
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
/**
 * Format of 32bits Init Sequence Number of SYN packet
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |      Hash for Validating      |      Hash for randomizing     |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#include <stdlib.h>

#include "scan-modules.h"
#include "../cookie.h"
#include "../templ/templ-tcp.h"
#include "../util/mas-safefunc.h"
#include "../util/mas-malloc.h"
#include "../util/logger.h"

extern struct ScanModule ZBannerScan; /*for internal x-ref*/

static int
zbanner_global_init()
{
    if (!ZBannerScan.probe) {
        LOG(0, "FAIL: No ProbeModule was specified.\n");
        LOG(0, "    Hint: specify ProbeModule like `--probe-module null`.\n");
        return 0;
    }
    return 1;
}

static int
zbanner_make_packet(
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

    /*`index` is unused now*/
    unsigned seqno = get_cookie(ip_them, port_them, ip_me, port_me, entropy);

    *r_length = tcp_create_packet(
        ip_them, port_them, ip_me, port_me,
        seqno, 0, TCP_FLAG_SYN,
        NULL, 0, px, sizeof_px);
    
    /*no need do send again in this moment*/
    return 0;
}

static int
zbanner_filter_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned is_myip, unsigned is_myport)
{
    /*record packet to our source port*/
    if (parsed->found == FOUND_TCP && is_myip && is_myport)
        return 1;
    
    return 0;
}

static int
zbanner_validate_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px)
{
    ipaddress ip_me    = parsed->dst_ip;
    ipaddress ip_them  = parsed->src_ip;
    unsigned port_me   = parsed->port_dst;
    unsigned port_them = parsed->port_src;
    unsigned seqno_me  = TCP_ACKNO(px, parsed->transport_offset);

    uint16_t validate_hash  = get_cookie(ip_them, port_them, ip_me, port_me, entropy)>>16;
    uint16_t seqno_me_vhash = seqno_me>>16;

	/*Just validate the first 2 bytes to leave all correspond packets*/
    if (validate_hash == seqno_me_vhash)
        return 1;

    return 0;
}

static int
zbanner_dedup_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    ipaddress *ip_them, unsigned *port_them,
    ipaddress *ip_me, unsigned *port_me, unsigned *type)
{
    /*
     * Simply differ from before and after contructing TCP conn.
     * Maybe it can make RST(for probe) same with SYNACK and
     * RST(for SYN). But we can also recognize open/closed port
     * and get banner from the first packet with data.
     * 
     * However, all relative packets could be save to pcap file
     * if we want.*/

    if (parsed->app_length)
        *type = 0;
    else
        *type = 1;
    return 1;
}

static int
zbanner_handle_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    item->ip_them   = parsed->src_ip;
    item->port_them = parsed->port_src;
    item->ip_me     = parsed->dst_ip;
    item->port_me   = parsed->port_dst;

    /*SYNACK*/
    if (TCP_HAS_FLAG(px, parsed->transport_offset, TCP_FLAG_SYN|TCP_FLAG_ACK)) {
        item->is_success = 1;
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "syn-ack");
        /*check for zero window of synack*/
        uint16_t win_them = TCP_WIN(px, parsed->transport_offset);
        if (win_them == 0) {
            safe_strcpy(item->classification, OUTPUT_CLS_LEN, "zerowin");
            return 0;
        } else {
            safe_strcpy(item->classification, OUTPUT_CLS_LEN, "open");
            return 1;
        }
    }

    /*RST for SYN. (RST for probe was deduped.)*/
    if (TCP_HAS_FLAG(px, parsed->transport_offset, TCP_FLAG_RST)) {
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "rst");
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "closed");
        return 0;
    }

    /*Banner*/
    if (parsed->app_length) {
        /*
        * We could recv Response DATA with some combinations of TCP flags
        * 1.[ACK]: maybe more data
        * 2.[PSH, ACK]: no more data
        * 3.[FIN, PSH, ACK]: no more data and disconnecting
        */
        item->is_success = 1;
        tcp_flags_to_string(TCP_FLAGS(px, parsed->transport_offset),
            item->reason, OUTPUT_RSN_LEN);
        safe_strcpy(
            item->classification, OUTPUT_CLS_LEN, ZBannerScan.probe->name);

        if (ZBannerScan.probe->handle_response_cb) {

            ipaddress ip_me    = parsed->dst_ip;
            ipaddress ip_them  = parsed->src_ip;
            unsigned port_me   = parsed->port_dst;
            unsigned port_them = parsed->port_src;

            ZBannerScan.probe->handle_response_cb(
                ip_them, port_them, ip_me, port_me,
                &px[parsed->app_offset], parsed->app_length,
                item->report, OUTPUT_RPT_LEN);
        }

        return 1;
    }

    return 0;
}

static int
zbanner_response_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned char *r_px, unsigned sizeof_r_px,
    size_t *r_length, unsigned index)
{
    ipaddress ip_me      = parsed->dst_ip;
    ipaddress ip_them    = parsed->src_ip;
    unsigned  port_me    = parsed->port_dst;
    unsigned  port_them  = parsed->port_src;
    unsigned  seqno_me   = TCP_ACKNO(px, parsed->transport_offset);
    unsigned  seqno_them = TCP_SEQNO(px, parsed->transport_offset);

    if (parsed->app_length) {
        /*send rst*/
        *r_length = tcp_create_packet(
            ip_them, port_them, ip_me, port_me,
            seqno_me, 0, TCP_FLAG_RST,
            NULL, 0, r_px, sizeof_r_px);
    } else {
        /*send probe*/

        unsigned char payload[PROBE_PAYLOAD_MAX_LEN];
        size_t payload_len = 0; 

        if (ZBannerScan.probe->make_payload_cb) {
            payload_len = ZBannerScan.probe->make_payload_cb(
                ip_them, port_them, ip_me, port_me,
                0, /*zbanner can recognize reponse by itself*/
                payload, PROBE_PAYLOAD_MAX_LEN);
        }
        
        *r_length = tcp_create_packet(
            ip_them, port_them, ip_me, port_me,
            seqno_me, seqno_them+1, TCP_FLAG_ACK,
            payload, payload_len, r_px, sizeof_r_px);
    }

    /*one reponse is enough*/
    return 0;
}

struct ScanModule ZBannerScan = {
    .name = "zbanner",
    .desc =
        "ZBannerScan tries to contruct TCP conn with target port and send data "
        "from specified ProbeModule. Data in first reponse packet will be handled"
        " by specified ProbeModule.\n"
        "What important is the whole process was done in completely stateless. "
        "So ZBannerScan is very fast for large-scale probing like banner grabbing,"
        " service identification and etc.\n\n"
        "Must specify a ProbeModule for ZBannerScan like:\n"
        "    `--probe-module null`\n\n"
        "ZBannerScan will construct complete TCP conns. So must avoid Linux system "
        "sending RST automatically by adding iptable rule like:\n"
        "    `sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP -s <src-ip>`\n"
        "Line number of added rule could be checked like:\n"
        "    `sudo iptables -L --line-numbers`\n"
        "Remove the rule by its line number if we do not need it:\n"
        "    `sudo iptables -D OUTPUT <line-number>`\n",

    .global_init_cb = &zbanner_global_init,
    .rx_thread_init_cb = NULL,
    .tx_thread_init_cb = NULL,

    .make_packet_cb = &zbanner_make_packet,

    .filter_packet_cb = &zbanner_filter_packet,
    .validate_packet_cb = &zbanner_validate_packet,
    .dedup_packet_cb = &zbanner_dedup_packet,
    .handle_packet_cb = &zbanner_handle_packet,
    .response_packet_cb = &zbanner_response_packet,

    .close_cb = NULL,
};
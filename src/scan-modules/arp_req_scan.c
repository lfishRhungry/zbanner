#include <stdlib.h>
#include <string.h>

#include "arp_req_scan.h"
#include "../cookie.h"
#include "../templ/templ-arp.h"
#include "../util/mas-safefunc.h"
#include "../util/mas-malloc.h"

extern struct ScanModule ArpReqScan; /*for internal x-ref*/

static int
arpreq_make_packet(
    unsigned cur_proto,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    uint64_t entropy, unsigned index,
    unsigned char *px, unsigned sizeof_px, size_t *r_length)
{
    /*we do not need a cookie and actually cannot set it*/

    *r_length = arp_create_request_packet(ip_them, ip_me, px, sizeof_px);
    
    /*no need do send again in this moment*/
    return 0;
}

static int
arpreq_filter_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned is_myip, unsigned is_myport)
{
    /*I do not think we should care about any other types of arp packet.*/
    if (parsed->found==FOUND_ARP && is_myip
        && parsed->opcode==ARP_OPCODE_REPLY) {
        return 1;
    }
    
    return 0;
}

/**
 * Unfortunately, we cannot validate arp replies with a good way, but getting all
 * replies does not seem to be a bad thing.
*/

static int
arpreq_dedup_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    ipaddress *ip_them, unsigned *port_them,
    ipaddress *ip_me, unsigned *port_me, unsigned *type)
{
    return 1;
}

static int
arpreq_handle_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned *successed,
    char *classification, unsigned cls_length,
    char *report, unsigned rpt_length)
{
    *successed = 1;
    safe_strcpy(classification, cls_length, "arp reply");
    snprintf(report, rpt_length, "mac addr: %02X:%02X:%02X:%02X:%02X:%02X",
        parsed->mac_src[0], parsed->mac_src[1], parsed->mac_src[2],
        parsed->mac_src[3], parsed->mac_src[4], parsed->mac_src[5]);

    /*no need to response*/
    return 0;
}

struct ScanModule ArpReqScan = {
    .name = "arpreq",
    .description =
        "ArpReqScan sends an ARP Request packet to broadcast mac addr"
        "(all zero) with target ipv4 addr we request. Expect an ARP Reply packet "
        "with actual mac addr of requested target and print mac addr as report. "
        "ArpReqScan does not support ipv6 target because ipv6 use neighbor "
        "discovery messages of Neighbor Dicovery Protocol(NDP) implemented by ICMPv6 "
        " to dicovery neighbors and their mac addr. ArpReqScan will ignore ipv6 "
        "targets.\n",

    .global_init_cb = NULL,
    .rx_thread_init_cb = NULL,
    .tx_thread_init_cb = NULL,

    .make_packet_cb = arpreq_make_packet,

    .filter_packet_cb = arpreq_filter_packet,
    .validate_packet_cb = NULL,
    .dedup_packet_cb = arpreq_dedup_packet,
    .handle_packet_cb = arpreq_handle_packet,
    .response_packet_cb = NULL,

    .close_cb = NULL,
};
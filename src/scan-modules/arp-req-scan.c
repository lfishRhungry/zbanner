#include <stdlib.h>
#include <string.h>

#include "scan-modules.h"
#include "../cookie.h"
#include "../templ/templ-arp.h"
#include "../util/mas-safefunc.h"
#include "../util/mas-malloc.h"

extern struct ScanModule ArpReqScan; /*for internal x-ref*/

static int
arpreq_transmit(
    uint64_t entropy,
    struct ScanTarget *target,
    unsigned char *px, size_t *len)
{
    /*we do not need a cookie and actually cannot set it*/
    *len = arp_create_request_packet(
        target->ip_them, target->ip_me, px, PKT_BUF_LEN);

    return 0;
}

static void
arpreq_validate(
    uint64_t entropy,
    struct Received *recved,
    struct PreHandle *pre)
{
    /*do not care about any other types of arp packet.*/
    if (recved->parsed.found == FOUND_ARP
        && recved->is_myip
        && recved->parsed.opcode == ARP_OPCODE_REPLY)
        pre->go_record = 1;
    else return;
    
    pre->go_dedup  = 1;
}

static void
arpreq_handle(
    uint64_t entropy,
    struct Received *recved,
    struct OutputItem *item,
    struct stack_t *stack)
{
    item->port_them  = 0;
    item->port_me    = 0;
    item->is_success = 1;

    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "arp reply");
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "alive");
    snprintf(item->report, OUTPUT_RPT_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
        recved->parsed.mac_src[0], recved->parsed.mac_src[1],
        recved->parsed.mac_src[2], recved->parsed.mac_src[3],
        recved->parsed.mac_src[4], recved->parsed.mac_src[5]);
}

struct ScanModule ArpReqScan = {
    .name = "arpreq",
    .required_probe_type = 0,
    .bpf_filter = "arp && arp[6:2]==2", /*arp reply*/
    .desc =
        "ArpReqScan sends an ARP Request packet to broadcast mac addr"
        "(all one) with target ipv4 addr we request. Expect an ARP Reply packet "
        "with actual mac addr of requested target and print mac addr as report. "
        "ArpReqScan does not support ipv6 target because ipv6 use neighbor "
        "discovery messages of Neighbor Dicovery Protocol(NDP) implemented by ICMPv6 "
        " to dicovery neighbors and their mac addr. ArpReqScan will ignore ipv6 "
        "targets.\n"
        "NOTE: ArpReqScan works in local area network only, so remember to use\n"
        "    `--lan-mode`\n"
        "or to set router mac like:\n"
        "    `--router-mac ff-ff-ff-ff-ff-ff`.\n",

    .global_init_cb    = &scan_init_nothing,
    .transmit_cb       = &arpreq_transmit,
    .validate_cb       = &arpreq_validate,
    .handle_cb         = &arpreq_handle,
    .close_cb          = &scan_close_nothing,
};
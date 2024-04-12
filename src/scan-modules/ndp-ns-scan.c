#include <stdlib.h>

#include "scan-modules.h"
#include "../xconf.h"
#include "../massip/massip-cookie.h"
#include "../version.h"
#include "../templ/templ-ndp.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"

extern struct ScanModule NdpNsScan; /*for internal x-ref*/

static macaddress_t src_mac;

static bool
ndpns_global_init(const struct Xconf *xconf)
{
    if (xconf->nic.link_type!=1) {
        LOG(LEVEL_ERROR, "[-] NdpNsScan cannot work on non-ethernet link type.\n");
        return false;
    }

    src_mac = xconf->nic.source_mac;
    return true;
}

static bool
ndpns_transmit(
    uint64_t entropy,
    struct ScanTarget *target,
    struct ScanTmEvent *event,
    unsigned char *px, size_t *len)
{
    /*ndp ns is just for ipv6*/
    if (target->ip_them.version!=6)
        return false; 

    /*no cookie for NDP NS*/

    *len = ndp_create_ns_packet(
        target->ip_them, target->ip_me, src_mac,
        255, px, PKT_BUF_LEN);
    
    /*add timeout*/
    event->need_timeout = 1;
    event->port_them    = 0;
    event->port_me      = 0;

    return false;
}

static void
ndpns_validate(
    uint64_t entropy,
    struct Received *recved,
    struct PreHandle *pre)
{
    /*record icmpv4 to my ip*/
    if (recved->parsed.found == FOUND_NDPv6
        && recved->is_myip
        && recved->parsed.src_ip.version==6)
        pre->go_record = 1;
    else return;

    /*validate both for ICMPv6 type, code and is it for solicitation*/
    if (recved->parsed.icmp_type==ICMPv6_TYPE_NA
        &&recved->parsed.icmp_code==ICMPv6_CODE_NA
        && ndp_is_solicited_advertise(recved->parsed.src_ip.ipv6,
            recved->packet, recved->parsed.transport_offset)) {
        pre->go_dedup = 1;
        pre->dedup_port_them = 0;
        pre->dedup_port_me   = 0;
    }
}

static void
ndpns_handle(
    unsigned th_idx,
    uint64_t entropy,
    struct Received *recved,
    struct OutputItem *item,
    struct stack_t *stack,
    struct FHandler *handler)
{
    item->port_them  = 0;
    item->port_me    = 0;
    item->level      = Output_SUCCESS;

    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "ndp na");
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "alive");

    /*check whether from router
      and extract mac addr from ICMPv6 Option: Target link-layer address*/
    if (NDP_NA_HAS_FLAG(recved->packet, recved->parsed.transport_offset, NDP_NA_FLAG_ROUTER)) {
        snprintf(item->report, OUTPUT_RPT_LEN, "%02X:%02X:%02X:%02X:%02X:%02X from router",
            recved->packet[recved->parsed.transport_offset+26],
            recved->packet[recved->parsed.transport_offset+27],
            recved->packet[recved->parsed.transport_offset+28],
            recved->packet[recved->parsed.transport_offset+29],
            recved->packet[recved->parsed.transport_offset+30],
            recved->packet[recved->parsed.transport_offset+31]);
    } else {
        snprintf(item->report, OUTPUT_RPT_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
            recved->packet[recved->parsed.transport_offset+26],
            recved->packet[recved->parsed.transport_offset+27],
            recved->packet[recved->parsed.transport_offset+28],
            recved->packet[recved->parsed.transport_offset+29],
            recved->packet[recved->parsed.transport_offset+30],
            recved->packet[recved->parsed.transport_offset+31]);
    }
}

void ndpns_timeout(
    uint64_t entropy,
    struct ScanTmEvent *event,
    struct OutputItem *item,
    struct stack_t *stack,
    struct FHandler *handler)
{
    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "down");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "timeout");
}

struct ScanModule NdpNsScan = {
    .name                = "ndp-ns",
    .required_probe_type = 0,
    .support_timeout     = 1,
    .params              = NULL,
    .bpf_filter          = "icmp6 && (icmp6[0]==136 && icmp6[1]==0)", /*ndp neighbor advertisement*/
    .desc =
        "NdpNsScan sends an NDP(ICMPv6) Neighbor Solicitation to IPv6 target "
        "host(actually `the solicited-node multicast address`). Expect an NDP"
        "Neighbor Advertisement to believe the host is alive.\n"
        "We must set an IPv6 link-local address as source IP. And it's better"
        "  to set `--fake-router-mac` to avoid "XTATE_FIRST_UPPER_NAME" to "
        "resolve router MAC address to a non link-local IPv6 and warn us.\n"
        "HINT: Sometimes we want to check if target host is reachable with link-"
        "local IPv6 address, we can use Ping tool to do this by specifying link-"
        "local IPv6 address of target while setting our link-local IPv6 address "
        "and interface explicitly.\n"
        "Example on Linux:\n"
        "      ping -6 <dst-IPv6-addr> -I <src-IPv6-addr>%<interface>\n"
        "Example on Windows:\n"
        "      ping -6 <dst-IPv6-addr> -S <src-IPv6-addr>%<interface-num>",

    .global_init_cb         = &ndpns_global_init,
    .transmit_cb            = &ndpns_transmit,
    .validate_cb            = &ndpns_validate,
    .handle_cb              = &ndpns_handle,
    .timeout_cb             = &ndpns_timeout,
    .poll_cb                = &scan_poll_nothing,
    .close_cb               = &scan_close_nothing,
};
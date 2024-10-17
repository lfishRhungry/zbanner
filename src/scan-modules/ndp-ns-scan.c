#include <stdlib.h>

#include "scan-modules.h"
#include "../xconf.h"
#include "../target/target-cookie.h"
#include "../version.h"
#include "../templ/templ-ndp.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"

extern Scanner NdpNsScan; /*for internal x-ref*/

static macaddress_t src_mac;

struct NdpNsConf {
    unsigned record_ttl : 1;
};

static struct NdpNsConf ndpns_conf = {0};

static ConfRes SET_record_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    ndpns_conf.record_ttl = parseBoolean(value);

    return Conf_OK;
}

static ConfParam ndpns_parameters[] = {
    {"record-ttl",
     SET_record_ttl,
     Type_BOOL,
     {"ttl", 0},
     "Records Hop Limit for IPv6 in NDP NA of ICMPv6."},

    {0}};

static bool ndpns_init(const XConf *xconf) {

    if (xconf->nic.link_type != 1) {
        LOG(LEVEL_ERROR, "NdpNsScan cannot work on non-ethernet link type.\n");
        return false;
    }

    src_mac = xconf->nic.source_mac;
    return true;
}

static bool ndpns_transmit(uint64_t entropy, ScanTarget *target,
                           ScanTmEvent *event, unsigned char *px, size_t *len) {
    if (target->target.ip_proto != IP_PROTO_Other)
        return false;

    /*ndp ns is just for ipv6*/
    if (target->target.ip_them.version != 6)
        return false;

    /*no cookie for NDP NS*/

    *len = ndp_create_ns_packet(target->target.ip_them, target->target.ip_me,
                                src_mac, 0, px, PKT_BUF_SIZE);

    /*add timeout*/
    event->need_timeout     = 1;
    event->target.port_them = 0;
    event->target.port_me   = 0;

    return false;
}

static void ndpns_validate(uint64_t entropy, Recved *recved, PreHandle *pre) {
    /*record icmpv4 to my ip*/
    if (recved->parsed.found == FOUND_NDPv6 && recved->is_myip &&
        recved->parsed.src_ip.version == 6)
        pre->go_record = 1;
    else
        return;

    /*validate both for ICMPv6 type, code and is it for solicitation*/
    if (recved->parsed.icmp_type == ICMPv6_TYPE_NA &&
        recved->parsed.icmp_code == ICMPv6_CODE_NA &&
        ndp_is_solicited_advertise(recved->parsed.src_ip.ipv6, recved->packet,
                                   recved->parsed.transport_offset)) {
        pre->go_dedup        = 1;
        pre->dedup_port_them = 0;
        pre->dedup_port_me   = 0;
    }
}

static void ndpns_handle(unsigned th_idx, uint64_t entropy, Recved *recved,
                         OutItem *item, STACK *stack, FHandler *handler) {
    item->target.port_them = 0;
    item->target.port_me   = 0;
    item->no_port          = 1;
    item->level            = OUT_SUCCESS;

    safe_strcpy(item->reason, OUT_RSN_SIZE, "ndp na");
    safe_strcpy(item->classification, OUT_CLS_SIZE, "alive");

    dach_printf(&item->report, "mac_addr", LinkType_String,
                "%02X:%02X:%02X:%02X:%02X:%02X",
                recved->packet[recved->parsed.transport_offset + 26],
                recved->packet[recved->parsed.transport_offset + 27],
                recved->packet[recved->parsed.transport_offset + 28],
                recved->packet[recved->parsed.transport_offset + 29],
                recved->packet[recved->parsed.transport_offset + 30],
                recved->packet[recved->parsed.transport_offset + 31]);

    if (NDP_NA_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
                        NDP_NA_FLAG_ROUTER)) {
        dach_set_bool(&item->report, "from_router", true);
    } else {
        dach_set_bool(&item->report, "from_router", false);
    }

    if (ndpns_conf.record_ttl)
        dach_set_int(&item->report, "ttl", recved->parsed.ip_ttl);
}

static void ndpns_timeout(uint64_t entropy, ScanTmEvent *event, OutItem *item,
                          STACK *stack, FHandler *handler) {
    item->no_port = 1;
    item->level   = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "down");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "timeout");
}

Scanner NdpNsScan = {
    .name                = "ndp-ns",
    .required_probe_type = 0,
    .support_timeout     = 1,
    .params              = ndpns_parameters,
    /*ndp neighbor advertisement*/
    .bpf_filter          = "icmp6 && (icmp6[0]==136 && icmp6[1]==0)",
    .short_desc          = "NDP scan for local network.",
    .desc =
        "NdpNsScan sends an NDP(ICMPv6) Neighbor Solicitation to IPv6 target "
        "host(actually `the solicited-node multicast address`). Expect an NDP"
        "Neighbor Advertisement to believe the host is alive.\n"
        "We must set an IPv6 link-local address as source IP. And it's better"
        "  to set `--fake-router-mac` to avoid " XTATE_NAME_TITLE_CASE " to "
        "resolve router MAC address to a non link-local IPv6 and warn us.\n"
        "HINT: Sometimes we want to check if target host is reachable with "
        "link-"
        "local IPv6 address, we can use Ping tool to do this by specifying "
        "link-"
        "local IPv6 address of target while setting our link-local IPv6 "
        "address "
        "and interface explicitly.\n"
        "Example on Linux:\n"
        "      ping -6 <dst-IPv6-addr> -I <src-IPv6-addr>%<interface>\n"
        "Example on Windows:\n"
        "      ping -6 <dst-IPv6-addr> -S <src-IPv6-addr>%<interface-num>\n"
        "NOTE: Don't specify any ports for this module.",

    .init_cb     = &ndpns_init,
    .transmit_cb = &ndpns_transmit,
    .validate_cb = &ndpns_validate,
    .handle_cb   = &ndpns_handle,
    .timeout_cb  = &ndpns_timeout,
    .poll_cb     = &scan_poll_nothing,
    .close_cb    = &scan_close_nothing,
    .status_cb   = &scan_no_status,
};
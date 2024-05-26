#include <stdlib.h>

#include "scan-modules.h"
#include "../xconf.h"
#include "../massip/massip-cookie.h"
#include "../templ/templ-icmp.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"

extern struct ScanModule IcmpEchoScan; /*for internal x-ref*/

struct IcmpEchoConf {
    unsigned record_ttl:1;
    unsigned record_ipid:1;
};

static struct IcmpEchoConf icmpecho_conf = {0};

static enum ConfigRes SET_record_ttl(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    icmpecho_conf.record_ttl = parseBoolean(value);

    return Conf_OK;
}

static enum ConfigRes SET_record_ipid(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    icmpecho_conf.record_ipid = parseBoolean(value);

    return Conf_OK;
}

static struct ConfigParam icmpecho_parameters[] = {
    {
        "record-ttl",
        SET_record_ttl,
        Type_BOOL,
        {"ttl", 0},
        "Records TTL for IPv4 in ICMP Timestamp."
    },
    {
        "record-ipid",
        SET_record_ipid,
        Type_BOOL,
        {"ipid", 0},
        "Records IPID of ICMP Timestamp for IPv4."
    },

    {0}
};

static bool
icmpecho_global_init(const struct Xconf *xconf)
{
    if (xconf->targets.count_ports!=1) {
        LOG(LEVEL_ERROR, "[-] IcmpEchoScan doesn't need to specify any ports.\n");
        return false;
    }

    return true;
}

static bool
icmpecho_transmit(
    uint64_t entropy,
    struct ScanTarget *target,
    struct ScanTmEvent *event,
    unsigned char *px, size_t *len)
{
    if (target->ip_proto != IP_PROTO_Other)
        return false;

    /*we do not care target port*/
    unsigned cookie = get_cookie(
        target->ip_them, 0, target->ip_me, 0, entropy);

    *len = icmp_create_echo_packet(
        target->ip_them, target->ip_me,
        cookie, cookie, 255, px, PKT_BUF_LEN);
    
    /*add timeout*/
    event->need_timeout = 1;
    event->port_them    = 0;
    event->port_me      = 0;

    return false;
}

static void
icmpecho_validate(
    uint64_t entropy,
    struct Received *recved,
    struct PreHandle *pre)
{
    /*record icmp to my ip*/
    if (recved->parsed.found == FOUND_ICMP
        && recved->is_myip)
        pre->go_record = 1;
    else return;
    
    ipaddress ip_them = recved->parsed.src_ip;
    ipaddress ip_me   = recved->parsed.dst_ip;
    unsigned cookie   = get_cookie(ip_them, 0, ip_me, 0, entropy);

    if (recved->parsed.src_ip.version==4
        &&recved->parsed.icmp_type==ICMPv4_TYPE_ECHO_REPLY
        &&recved->parsed.icmp_code==ICMPv4_CODE_ECHO_REPLY
        &&get_icmp_cookie(&recved->parsed, recved->packet)==cookie) {
        pre->go_dedup = 1;
        pre->dedup_port_them = 0;
        pre->dedup_port_me   = 0;
    } else if (recved->parsed.src_ip.version==6
        &&recved->parsed.icmp_type==ICMPv6_TYPE_ECHO_REPLY
        &&recved->parsed.icmp_code==ICMPv6_CODE_ECHO_REPLY
        &&get_icmp_cookie(&recved->parsed, recved->packet)==cookie) {
        pre->go_dedup = 1;
        pre->dedup_port_them = 0;
        pre->dedup_port_me   = 0;
    }
}

static void
icmpecho_handle(
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

    safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "echo reply");
    safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "alive");

    if (icmpecho_conf.record_ttl)
        dach_printf(&item->report, "ttl", true, "%d", recved->parsed.ip_ttl);
    if (icmpecho_conf.record_ipid && recved->parsed.src_ip.version==4)
        dach_printf(&item->report, "ipid", true, "%d", recved->parsed.ip_v4_id);
}

void icmpecho_timeout(
    uint64_t entropy,
    struct ScanTmEvent *event,
    struct OutputItem *item,
    struct stack_t *stack,
    struct FHandler *handler)
{
    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "down");
    safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "timeout");
}

struct ScanModule IcmpEchoScan = {
    .name                = "icmp-echo",
    .required_probe_type = 0,
    .support_timeout     = 1,
    .params              = icmpecho_parameters,
    .bpf_filter = /*icmp echo reply in ipv4 & ipv6*/
        "(icmp && (icmp[0]==0 && icmp[1]==0)) "
        "|| (icmp6 && (icmp6[0]==129 && icmp6[1]==0))",
    .desc =
        "IcmpEchoScan sends an ICMP ECHO Request packet to target host. Expect an "
        "ICMP ECHO Reply to believe the host is alive.\n"
        "NOTE: Don't specify any ports for this module.",

    .global_init_cb         = &icmpecho_global_init,
    .transmit_cb            = &icmpecho_transmit,
    .validate_cb            = &icmpecho_validate,
    .handle_cb              = &icmpecho_handle,
    .timeout_cb             = &icmpecho_timeout,
    .poll_cb                = &scan_poll_nothing,
    .close_cb               = &scan_close_nothing,
};
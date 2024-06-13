#include <stdlib.h>

#include "scan-modules.h"
#include "../xconf.h"
#include "../massip/massip-cookie.h"
#include "../templ/templ-icmp.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"

extern struct ScanModule IcmpTimeScan; /*for internal x-ref*/

struct IcmpTimeConf {
    unsigned record_ttl:1;
    unsigned record_ipid:1;
};

static struct IcmpTimeConf icmptime_conf = {0};

static enum ConfigRes SET_record_ttl(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    icmptime_conf.record_ttl = parseBoolean(value);

    return Conf_OK;
}

static enum ConfigRes SET_record_ipid(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    icmptime_conf.record_ipid = parseBoolean(value);

    return Conf_OK;
}

static struct ConfigParam icmptime_parameters[] = {
    {
        "record-ttl",
        SET_record_ttl,
        Type_BOOL,
        {"ttl", 0},
        "Records TTL for IPv4 or Hop Limit for IPv6 in ICMP Echo Reply."
    },
    {
        "record-ipid",
        SET_record_ipid,
        Type_BOOL,
        {"ipid", 0},
        "Records IPID of ICMP Echo Reply just for IPv4."
    },

    {0}
};

static bool
icmptime_global_init(const struct Xconf *xconf)
{
    if (xconf->targets.count_ports!=1) {
        LOG(LEVEL_ERROR, "[-] IcmpTimeScan doesn't need to specify any ports.\n");
        return false;
    }

    return true;
}

static bool
icmptime_transmit(
    uint64_t entropy,
    struct ScanTarget *target,
    struct ScanTmEvent *event,
    unsigned char *px, size_t *len)
{
    if (target->ip_proto != IP_PROTO_Other)
        return false;

    /*icmp timestamp is just for ipv4*/
    if (target->ip_them.version!=4)
        return 0; 

    /*we do not care target port*/
    unsigned cookie = get_cookie(
        target->ip_them, 0, target->ip_me, 0, entropy);

    *len = icmp_create_timestamp_packet(
        target->ip_them, target->ip_me,
        cookie, cookie, 255, px, PKT_BUF_LEN);

    /*add timeout*/
    event->need_timeout = 1;
    event->port_them    = 0;
    event->port_me      = 0;

    return false;
}

static void
icmptime_validate(
    uint64_t entropy,
    struct Received *recved,
    struct PreHandle *pre)
{
    /*record icmpv4 to my ip*/
    if (recved->parsed.found == FOUND_ICMP
        && recved->is_myip
        && recved->parsed.src_ip.version==4)
        pre->go_record = 1;
    else return;

    ipaddress ip_them = recved->parsed.src_ip;
    ipaddress ip_me   = recved->parsed.dst_ip;
    unsigned cookie   = get_cookie(ip_them, 0, ip_me, 0, entropy);

    if (recved->parsed.icmp_type==ICMPv4_TYPE_TIMESTAMP_REPLY
        &&recved->parsed.icmp_code==ICMPv4_CODE_TIMESTAMP_REPLY
        &&get_icmp_cookie(&recved->parsed, recved->packet)==cookie) {
        pre->go_dedup = 1;
        pre->dedup_port_them = 0;
        pre->dedup_port_me   = 0;
    }
}

static void
icmptime_handle(
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

    safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "timestamp reply");
    safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "alive");

    if (icmptime_conf.record_ttl)
        dach_printf(&item->report, "ttl", true, "%d", recved->parsed.ip_ttl);
    if (icmptime_conf.record_ipid && recved->parsed.src_ip.version==4)
        dach_printf(&item->report, "ipid", true, "%d", recved->parsed.ip_v4_id);
}

static void icmptime_timeout(
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

struct ScanModule IcmpTimeScan = {
    .name                = "icmp-time",
    .required_probe_type = 0,
    .support_timeout     = 1,
    .params              = icmptime_parameters,
    .bpf_filter = /*icmp timestamp reply in ipv4*/
        "icmp && (icmp[0]==14 && icmp[1]==0)",
    .desc =
        "IcmpTimeScan sends an ICMP Timestamp mesage to IPv4 target host. Expect an "
        "ICMP Timestamp Reply to believe the host is alive.\n"
        "NOTE: Don't specify any ports for this module.",

    .global_init_cb         = &icmptime_global_init,
    .transmit_cb            = &icmptime_transmit,
    .validate_cb            = &icmptime_validate,
    .handle_cb              = &icmptime_handle,
    .timeout_cb             = &icmptime_timeout,
    .poll_cb                = &scan_poll_nothing,
    .close_cb               = &scan_close_nothing,
};
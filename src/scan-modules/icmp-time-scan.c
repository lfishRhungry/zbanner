#include <stdlib.h>

#include "scan-modules.h"
#include "../massip/cookie.h"
#include "../templ/templ-icmp.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"

extern struct ScanModule IcmpTimeScan; /*for internal x-ref*/

static bool
icmptime_transmit(
    uint64_t entropy,
    struct ScanTarget *target,
    struct ScanTmEvent *event,
    unsigned char *px, size_t *len)
{
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
    ipaddress ip_me = recved->parsed.dst_ip;
    unsigned cookie = get_cookie(ip_them, 0, ip_me, 0, entropy);

    if (get_icmp_type(&recved->parsed)==ICMPv4_TYPE_TIMESTAMP_REPLY
        &&get_icmp_code(&recved->parsed)==ICMPv4_CODE_TIMESTAMP_REPLY
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

    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "timestamp reply");
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "alive");
}

void icmptime_timeout(
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

struct ScanModule IcmpTimeScan = {
    .name                = "icmp-time",
    .required_probe_type = 0,
    .support_timeout     = 1,
    .params              = NULL,
    .bpf_filter          = "icmp && (icmp[0]==14 && icmp[1]==0)", /*icmp timestamp reply*/
    .desc =
        "IcmpTimeScan sends an ICMP Timestamp mesage to IPv4 target host. Expect an "
        "ICMP Timestamp Reply to believe the host is alive.",

    .global_init_cb         = &scan_global_init_nothing,
    .transmit_cb            = &icmptime_transmit,
    .validate_cb            = &icmptime_validate,
    .handle_cb              = &icmptime_handle,
    .timeout_cb             = &icmptime_timeout,
    .poll_cb                = &scan_poll_nothing,
    .close_cb               = &scan_close_nothing,
};
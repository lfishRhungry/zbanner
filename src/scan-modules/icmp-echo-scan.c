#include <stdlib.h>

#include "scan-modules.h"
#include "../cookie.h"
#include "../templ/templ-icmp.h"
#include "../util/mas-safefunc.h"
#include "../util/mas-malloc.h"

extern struct ScanModule IcmpEchoScan; /*for internal x-ref*/

static int
icmpecho_transmit(
    uint64_t entropy,
    struct ScanTarget *target,
    unsigned char *px, size_t *len)
{
    /*we do not care target port*/
    unsigned cookie = get_cookie(
        target->ip_them, 0, target->ip_me, 0, entropy);

    *len = icmp_create_echo_packet(
        target->ip_them, target->ip_me,
        cookie, cookie, 255, px, PKT_BUF_LEN);

    return 0;
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
    ipaddress ip_me = recved->parsed.dst_ip;
    unsigned cookie = get_cookie(ip_them, 0, ip_me, 0, entropy);

    if (recved->parsed.src_ip.version==4
        &&get_icmp_type(&recved->parsed)==ICMPv4_TYPE_ECHO_REPLY
        &&get_icmp_code(&recved->parsed)==ICMPv4_CODE_ECHO_REPLY
        &&get_icmp_cookie(&recved->parsed, recved->packet)==cookie) {
        pre->go_dedup = 1;
    } else if (recved->parsed.src_ip.version==6
        &&get_icmp_type(&recved->parsed)==ICMPv6_TYPE_ECHO_REPLY
        &&get_icmp_code(&recved->parsed)==ICMPv6_CODE_ECHO_REPLY
        &&get_icmp_cookie(&recved->parsed, recved->packet)==cookie) {
        pre->go_dedup = 1;
    }
}

static void
icmpecho_handle(
    uint64_t entropy,
    struct Received *recved,
    struct OutputItem *item,
    struct stack_t *stack)
{
    item->port_them  = 0;
    item->port_me    = 0;
    item->is_success = 1;

    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "echo reply");
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "alive");
}

struct ScanModule IcmpEchoScan = {
    .name = "icmpecho",
    .required_probe_type = 0,
    .desc =
        "IcmpEchoScan sends a ICMP ECHO Request packet to target host. Expect an "
        "ICMP ECHO Reply to believe the host is alive.\n",

    .global_init_cb         = &scan_init_nothing,
    .transmit_cb            = &icmpecho_transmit,
    .validate_cb            = &icmpecho_validate,
    .handle_cb              = &icmpecho_handle,
    .close_cb               = &scan_close_nothing,
};
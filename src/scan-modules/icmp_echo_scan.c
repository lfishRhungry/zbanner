#include <stdlib.h>

#include "scan_modules.h"
#include "../cookie.h"
#include "../templ/templ-icmp.h"
#include "../util/mas-safefunc.h"
#include "../util/mas-malloc.h"

extern struct ScanModule IcmpEchoScan; /*for internal x-ref*/

static int
icmpecho_make_packet(
    unsigned cur_proto,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    uint64_t entropy, unsigned index,
    unsigned char *px, unsigned sizeof_px, size_t *r_length)
{
    /*we do not care target port*/
    unsigned cookie = get_cookie(ip_them, 0, ip_me, 0, entropy);

    *r_length = icmp_create_echo_packet(ip_them, ip_me,
        cookie, cookie, 255, px, sizeof_px);
    
    /*no need do send again in this moment*/
    return 0;
}

static int
icmpecho_filter_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned is_myip, unsigned is_myport)
{
    if (parsed->found == FOUND_ICMP && is_myip) {
        return 1;
    }
    
    return 0;
}

static int
icmpecho_validate_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px)
{
    ipaddress ip_me = parsed->dst_ip;
    ipaddress ip_them = parsed->src_ip;
    unsigned cookie = get_cookie(ip_them, 0, ip_me, 0, entropy);

    if (parsed->src_ip.version==4
        &&get_icmp_type(parsed)==ICMPv4_TYPE_ECHO_REPLY
        &&get_icmp_code(parsed)==ICMPv4_CODE_ECHO_REPLY
        &&get_icmp_cookie(parsed,px)==cookie) {
        return 1;
    }

    if (parsed->src_ip.version==6
        &&get_icmp_type(parsed)==ICMPv6_TYPE_ECHO_REPLY
        &&get_icmp_code(parsed)==ICMPv6_CODE_ECHO_REPLY
        &&get_icmp_cookie(parsed,px)==cookie) {
        return 1;
    }

    return 0;
}

static int
icmpecho_dedup_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    ipaddress *ip_them, unsigned *port_them,
    ipaddress *ip_me, unsigned *port_me, unsigned *type)
{
    return 1;
}

static int
icmpecho_handle_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned *successed,
    char *classification, unsigned cls_length,
    char *report, unsigned rpt_length)
{
    *successed = 1;
    safe_strcpy(classification, cls_length, "echo reply");

    /*no need to response*/
    return 0;
}

struct ScanModule IcmpEchoScan = {
    .name = "icmpecho",
    .desc =
        "IcmpEchoScan sends a ICMP ECHO Request packet to target host. Expect an "
        "ICMP ECHO Reply to believe the host is alive.\n",

    .global_init_cb = NULL,
    .rx_thread_init_cb = NULL,
    .tx_thread_init_cb = NULL,

    .make_packet_cb = icmpecho_make_packet,

    .filter_packet_cb = icmpecho_filter_packet,
    .validate_packet_cb = icmpecho_validate_packet,
    .dedup_packet_cb = icmpecho_dedup_packet,
    .handle_packet_cb = icmpecho_handle_packet,
    .response_packet_cb = NULL,

    .close_cb = NULL,
};
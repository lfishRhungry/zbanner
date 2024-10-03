#include <stdlib.h>

#include "scan-modules.h"
#include "../xconf.h"
#include "../stub/stub-pcap-dlt.h"
#include "../target/target-cookie.h"
#include "../templ/templ-icmp.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"

/** echo request and reply ICMP(v4/v6) according to RFC792 and RFC4443.
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-

   We set fields in echo request packets as following:
    1.identifier: cookie of ip_them, ip_me and TTL for identifying response for
    us. TTL is used to avoid same `identifier` for same path.
    2.sequence: TTL. This is for identifying distance from ICMP echo reply.
    3.ipid: useless for us and set it to random.

   NOTE: The IP header wrapped in ICMP payload isn't be totally same as what we
   sent especially the TTL. And the TTL in IP header of ICMP Echo Reply isn't
   what we sent one, too. So we must save the initial TTL in a field of ICMP.
*/

extern Scanner YarrpEchoScan; /*for internal x-ref*/

struct YarrpEchoConf {
    unsigned record_ttl  : 1;
    unsigned record_ipid : 1;
};

static struct YarrpEchoConf yarrpecho_conf = {0};

static ConfRes SET_record_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpecho_conf.record_ttl = parseBoolean(value);

    return Conf_OK;
}

static ConfRes SET_record_ipid(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpecho_conf.record_ipid = parseBoolean(value);

    return Conf_OK;
}

static ConfParam yarrpecho_parameters[] = {
    {"record-ttl",
     SET_record_ttl,
     Type_BOOL,
     {"ttl", 0},
     "Records TTL for IPv4 or Hop Limit for IPv6 in ICMP Echo Reply or ICMP "
     "ttl/hop limit exceeded response."},
    {"record-ipid",
     SET_record_ipid,
     Type_BOOL,
     {"ipid", 0},
     "Records IPID just for IPv4 of ICMP Echo Reply or ICMP ttl/hop limit "
     "exceeded response."},

    {0}};

static bool yarrpecho_transmit(uint64_t entropy, ScanTarget *target,
                               ScanTmEvent *event, unsigned char *px,
                               size_t *len) {
    if (target->target.ip_proto != IP_PROTO_Other)
        return false;

    unsigned cookie =
        get_cookie(target->target.ip_them, target->target.port_them,
                   target->target.ip_me, 0, entropy);
    uint16_t id   = cookie & 0xFF;
    uint16_t ipid = cookie ^ entropy;

    *len = icmp_echo_create_packet(target->target.ip_them, target->target.ip_me,
                                   id, target->target.port_them, ipid,
                                   target->target.port_them, NULL, 0, px,
                                   PKT_BUF_SIZE);

    /*doesn't need timeout*/

    return false;
}

static void yarrpecho_validate(uint64_t entropy, Recved *recved,
                               PreHandle *pre) {
    /*record icmp to my ip*/
    if (recved->parsed.found == FOUND_ICMP && recved->is_myip)
        pre->go_record = 1;
    else
        return;

    /*echo reply*/
    if ((recved->parsed.src_ip.version == 4 &&
         recved->parsed.icmp_type == ICMPv4_TYPE_ECHO_REPLY &&
         recved->parsed.icmp_code == ICMPv4_CODE_ECHO_REPLY) ||
        (recved->parsed.src_ip.version == 6 &&
         recved->parsed.icmp_type == ICMPv6_TYPE_ECHO_REPLY &&
         recved->parsed.icmp_code == ICMPv6_CODE_ECHO_REPLY)) {

        ipaddress ip_them = recved->parsed.src_ip;
        ipaddress ip_me   = recved->parsed.dst_ip;
        unsigned  cookie =
            get_cookie(ip_them, recved->parsed.icmp_seq, ip_me, 0, entropy);

        if (recved->parsed.icmp_id == (cookie & 0xFF)) {
            pre->go_dedup        = 1;
            pre->dedup_port_them = recved->parsed.icmp_seq;
            pre->dedup_port_me   = 0;
        }

        return;
    }

    /*TTL exceeded*/
    if ((recved->parsed.src_ip.version == 4 &&
         recved->parsed.icmp_type == ICMPv4_TYPE_TTL_EXCEEDED &&
         recved->parsed.icmp_code == ICMPv4_CODE_TTL_EXCEEDED) ||
        (recved->parsed.src_ip.version == 6 &&
         recved->parsed.icmp_type == ICMPv6_TYPE_HOPLIMIT_EXCEEDED &&
         recved->parsed.icmp_code == ICMPv6_CODE_HOPLIMIT_EXCEEDED)) {

        PreInfo info = {0};
        if (preprocess_frame(recved->packet + recved->parsed.app_offset,
                             recved->length - recved->parsed.app_offset,
                             PCAP_DLT_RAW, &info)) {

            ipaddress ip_them = info.dst_ip;
            ipaddress ip_me   = info.src_ip;
            unsigned  cookie =
                get_cookie(ip_them, info.icmp_seq, ip_me, 0, entropy);

            if (info.icmp_id == (cookie & 0xFF)) {
                pre->go_dedup        = 1;
                pre->dedup_port_them = info.icmp_seq;
                pre->dedup_port_me   = 0;
            }
        }
    }
}

static void yarrpecho_handle(unsigned th_idx, uint64_t entropy, Recved *recved,
                             OutItem *item, STACK *stack, FHandler *handler) {
    item->target.port_them = 0;
    item->target.port_me   = 0;
    item->level            = OUT_SUCCESS;

    /*echo reply*/
    if ((recved->parsed.src_ip.version == 4 &&
         recved->parsed.icmp_type == ICMPv4_TYPE_ECHO_REPLY &&
         recved->parsed.icmp_code == ICMPv4_CODE_ECHO_REPLY) ||
        (recved->parsed.src_ip.version == 6 &&
         recved->parsed.icmp_type == ICMPv6_TYPE_ECHO_REPLY &&
         recved->parsed.icmp_code == ICMPv6_CODE_ECHO_REPLY)) {
        ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->target.ip_them);
        safe_strcpy(item->reason, OUT_RSN_SIZE, "echo reply");
        safe_strcpy(item->classification, OUT_CLS_SIZE, "destination");
        dach_set_int(&item->report, "distance", recved->parsed.icmp_seq);
        dach_append(&item->report, "destination", ip_them_fmt.string,
                    strlen(ip_them_fmt.string), LinkType_String);
    } else {
        /*ttl/hop limit exceeded*/
        PreInfo info = {0};
        preprocess_frame(recved->packet + recved->parsed.app_offset,
                         recved->length - recved->parsed.app_offset,
                         PCAP_DLT_RAW, &info);
        ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(info.dst_ip);
        safe_strcpy(item->reason, OUT_RSN_SIZE, "ttl exceeded");
        safe_strcpy(item->classification, OUT_CLS_SIZE, "path");
        dach_set_int(&item->report, "distance", info.icmp_seq);
        dach_append(&item->report, "destination", ip_them_fmt.string,
                    strlen(ip_them_fmt.string), LinkType_String);
    }

    if (yarrpecho_conf.record_ttl)
        dach_set_int(&item->report, "ttl", recved->parsed.ip_ttl);
    if (yarrpecho_conf.record_ipid && recved->parsed.src_ip.version == 4)
        dach_set_int(&item->report, "ipid", recved->parsed.ip_v4_id);
}

Scanner YarrpEchoScan = {
    .name                = "yarrp-echo",
    .required_probe_type = 0,
    .support_timeout     = 0,
    .params              = yarrpecho_parameters,
    /*icmp echo reply and ttl/hop limit exceeded in ipv4 & ipv6*/
    .bpf_filter = "(icmp && ((icmp[0]==0 && icmp[1]==0)||(icmp[0]==11 && "
                  "icmp[1]==0))) || (icmp6 && ((icmp6[0]==129 && "
                  "icmp6[1]==0)||(icmp6[0]==3 && icmp6[1]==0)))",
    .short_desc = "ICMP Ping to trace the route path statelessly.",
    .desc =
        "YarrpEcho sends ICMP ECHO Request packets with different TTL values "
        "to target hosts and expects ICMP Echo Rely or ICMP TTL/Hop Limit "
        "Exceeded message for tracing the route path. This scanner uses the "
        "core idea of the stateless traceroute tool Yarrp, so it sends all "
        "target/ttl combinations in random.\n"
        "NOTE1: YarrpEcho needs to specify TTL ranges manually by \"Other\" "
        "port type. E.g. `--port o:1-20` means TTL range from 1 to 20.\n"
        "NOTE2: We should care the network pressure of hosts in the path. "
        "Yarrp's completely stateless route tracing method would make close "
        "hop hosts being hit a lot.\n"
        "NOTE3: Proper TTL range is import both for efficiency and network "
        "pressure of target hosts. A big range may hit target hosts a lot.",

    .init_cb     = &scan_init_nothing,
    .transmit_cb = &yarrpecho_transmit,
    .validate_cb = &yarrpecho_validate,
    .handle_cb   = &yarrpecho_handle,
    .timeout_cb  = &scan_no_timeout,
    .poll_cb     = &scan_poll_nothing,
    .close_cb    = &scan_close_nothing,
    .status_cb   = &scan_no_status,
};
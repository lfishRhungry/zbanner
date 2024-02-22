#include <stdlib.h>

#include "scan-modules.h"
#include "../xconf.h"
#include "../cookie.h"
#include "../templ/templ-udp.h"
#include "../templ/templ-icmp.h"
#include "../util/mas-safefunc.h"
#include "../util/mas-malloc.h"
#include "../util/logger.h"

extern struct ScanModule UdpProbeScan; /*for internal x-ref*/

/**
 *For calc the conn index.
 * NOTE: We use a trick of src-port to differenciate multi-probes to avoid
 * mutual interference of connections.
 * Be careful to the source port range and probe num. Source port range is 16 in
 * default and can be set with flag `--source-port`.
*/
static unsigned src_port_start;

static int
udpprobe_global_init(const void *xconf)
{
    if (!UdpProbeScan.probe) {
        LOG(0, "FAIL: UdpProbeScan needs a specified udp ProbeModule.\n");
        LOG(0, "    Hint: specify ProbeModule like `--probe-module null`.\n");
        return 0;
    }

    if (UdpProbeScan.probe->type != ProbeType_UDP) {
        LOG(0, "FAIL: UdpProbeScan needs a udp type ProbeModule.\n");
        LOG(0, "    Current ProbeModule %s is %s type.\n",
            UdpProbeScan.probe->name, get_probe_type_name(UdpProbeScan.probe->type));
        return 0;
    }

    src_port_start = ((const struct Xconf *)xconf)->nic.src.port.first;

    return 1;
}

static void
udpprobe_transmit(
    unsigned cur_proto, uint64_t entropy,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    sendp_in_tx sendp, void * sendp_params)
{
    /*we just handle tcp target*/
    if (cur_proto != Proto_UDP)
        return;

    for (unsigned idx=0; idx < UdpProbeScan.probe->probe_num; idx++) {

        unsigned cookie = get_cookie(ip_them, port_them, ip_me,
            src_port_start+idx, entropy);
        unsigned char payload[PROBE_PAYLOAD_MAX_LEN];
        size_t payload_len = 0;
        if (UdpProbeScan.probe->make_payload_cb) {
            payload_len = UdpProbeScan.probe->make_payload_cb(
                ip_them, port_them, ip_me, port_me,
                cookie, port_me-src_port_start,
                payload, PROBE_PAYLOAD_MAX_LEN);
        }

        unsigned char px[2048];
        size_t length = udp_create_packet(
            ip_them, port_them, ip_me, src_port_start+idx,
            payload, payload_len, px, 2048);

        sendp(sendp_params, px, length);
    }
    
}

static void
udpprobe_validate(
    uint64_t entropy,
    struct Received *recved,
    struct PreHandle *pre)
{
    /*record packet to our source port*/
    if (recved->parsed.found == FOUND_UDP
        && recved->is_myip
        && recved->is_myport) {
        pre->go_record = 1;
        ipaddress ip_them  = recved->parsed.src_ip;
        ipaddress ip_me    = recved->parsed.dst_ip;
        unsigned port_them = recved->parsed.port_src;
        unsigned port_me   = recved->parsed.port_dst;
        unsigned cookie    = get_cookie(ip_them, port_them, ip_me, port_me, entropy);

        if (UdpProbeScan.probe->validate_response_cb(
            ip_them, port_them, ip_me, port_me,
            cookie, port_me-src_port_start,
            &recved->packet[recved->parsed.app_offset],
            recved->parsed.app_length))
            pre->go_dedup = 1;
        else return;
    }
    
    /*record ICMP (udp) port unreachable message*/
    if (recved->parsed.found != FOUND_ICMP
        || !recved->is_myip)
        return;

    if (recved->parsed.dst_ip.version == 4
        && get_icmp_type(&recved->parsed)==ICMPv4_TYPE_ERR
        && get_icmp_code(&recved->parsed)==ICMPv4_CODE_ERR_PORT_UNREACHABLE) {

    } else if (recved->parsed.dst_ip.version == 6
        && get_icmp_type(&recved->parsed)==ICMPv6_TYPE_ERR
        && get_icmp_code(&recved->parsed)==ICMPv6_CODE_ERR_PORT_UNREACHABLE) {

    } else return;

    unsigned proto;
    parse_icmp_port_unreachable(
        &recved->packet[recved->parsed.transport_offset],
        recved->parsed.transport_length,
        &pre->dedup_ip_them, &pre->dedup_port_them,
        &pre->dedup_ip_me, &pre->dedup_port_me, &proto);
    if (proto==Proto_UDP) {
        pre->go_record = 1;
        pre->go_dedup = 1;
    }
}

static void
udpprobe_handle(
    uint64_t entropy,
    struct Received *recved,
    struct OutputItem *item,
    struct stack_t *stack)
{
    item->is_success = 1;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "open");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "udp reponse");

    ipaddress ip_them  = recved->parsed.src_ip;
    ipaddress ip_me    = recved->parsed.dst_ip;
    unsigned port_them = recved->parsed.port_src;
    unsigned port_me   = recved->parsed.port_dst;

    UdpProbeScan.probe->handle_response_cb(
        ip_them, port_them, ip_me, port_me,
        port_me-src_port_start,
        &recved->packet[recved->parsed.app_offset],
        recved->parsed.app_length,
        item->report, OUTPUT_RPT_LEN);
}

struct ScanModule UdpProbeScan = {
    .name = "udpprobe",
    .required_probe_type = ProbeType_UDP,
    .desc =
        "UdpProbeScan sends a udp packet with ProbeModule data to target port "
        "and expects a udp response to believe the port is open or an icmp port "
        "unreachable message if closed. Responsed data will be processed and "
        "formed a report by ProbeModule.\n"
        "UdpProbeScan prefer the first reponse udp packet. But all packets to us "
        "could be record to pcap file.\n",

    .global_init_cb = &udpprobe_global_init,
    .rx_thread_init_cb = &scan_init_nothing,
    .tx_thread_init_cb = &scan_init_nothing,
    .transmit_cb = &udpprobe_transmit,
    .validate_cb = &udpprobe_validate,
    .handle_cb = &udpprobe_handle,
    .close_cb = &scan_close_nothing,
};
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

static int
udpprobe_make_packet(
    unsigned cur_proto,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    uint64_t entropy, unsigned index,
    unsigned char *px, unsigned sizeof_px, size_t *r_length)
{
    /*we just handle tcp target*/
    if (cur_proto != Proto_UDP) {
        *r_length = 0;
        return 0;
    }

    unsigned cookie = get_cookie(ip_them, port_them, ip_me,
        src_port_start+index, entropy);
    
    unsigned char payload[PROBE_PAYLOAD_MAX_LEN];
    size_t payload_len = 0;
    if (UdpProbeScan.probe->make_payload_cb) {
        payload_len = UdpProbeScan.probe->make_payload_cb(
            ip_them, port_them, ip_me, port_me,
            cookie, port_me-src_port_start,
            payload, PROBE_PAYLOAD_MAX_LEN);
    }

    *r_length = udp_create_packet(
        ip_them, port_them, ip_me, src_port_start+index,
        payload, payload_len, px, sizeof_px);
        
    /*multi-probing for a target*/
    if (index<UdpProbeScan.probe->multi_index)
        return 1;

    return 0;
}

static int
udpprobe_filter_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned is_myip, unsigned is_myport)
{
    /*record packet to our source port*/
    if (parsed->found == FOUND_UDP && is_myip && is_myport)
        return 1;
    
    /*record ICMP (udp) port unreachable message*/
    if (parsed->found == FOUND_ICMP && is_myip) {
        if (parsed->dst_ip.version == 4) {
            if (get_icmp_type(parsed)==ICMPv4_TYPE_ERR
                && get_icmp_code(parsed)==ICMPv4_CODE_ERR_PORT_UNREACHABLE) {
                if (Proto_UDP==get_icmp_port_unreachable_proto(
                    &px[parsed->transport_offset], parsed->transport_length))
                    return 1;
            }
        }
        if (parsed->dst_ip.version == 6) {
            if (get_icmp_type(parsed)==ICMPv6_TYPE_ERR
                && get_icmp_code(parsed)==ICMPv6_CODE_ERR_PORT_UNREACHABLE) {
                if (Proto_UDP==get_icmp_port_unreachable_proto(
                    &px[parsed->transport_offset], parsed->transport_length))
                    return 1;
            }
        }
    }
    
    return 0;
}

static int
udpprobe_validate_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px)
{
    /*just validate udp response*/
    if (parsed->found == FOUND_UDP) {
        ipaddress ip_me     = parsed->dst_ip;
        ipaddress ip_them   = parsed->src_ip;
        unsigned  port_me   = parsed->port_dst;
        unsigned  port_them = parsed->port_src;
        unsigned  cookie    = get_cookie(ip_them, port_them, ip_me, port_me, entropy);

        if (UdpProbeScan.probe->validate_response_cb) {
            return UdpProbeScan.probe->validate_response_cb(
                ip_them, port_them, ip_me, port_me,
                cookie, port_me-src_port_start,
                &px[parsed->app_offset], parsed->app_length);
        }
    }

    /*icmp message cannot be validated nice*/
    if (parsed->found == FOUND_ICMP)
        return 1;

    return 0;
}

static int
udpprobe_dedup_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    ipaddress *ip_them, unsigned *port_them,
    ipaddress *ip_me, unsigned *port_me, unsigned *type)
{
    if (parsed->found == FOUND_ICMP) {
        unsigned proto;
        parse_icmp_port_unreachable(
            &px[parsed->transport_offset], parsed->transport_length,
            ip_them, port_them, ip_me, port_me, &proto);
    }
    /*just care the first udp response*/
    return 1;
}

static int
udpprobe_handle_packet(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (parsed->found==FOUND_ICMP) {
        unsigned proto;
        parse_icmp_port_unreachable(
            &px[parsed->transport_offset], parsed->transport_length,
            &item->ip_them, &item->port_them,
            &item->ip_me, &item->port_me, &proto);
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "closed");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "port unreachable");
        /*no reponse*/
        return 0;
    }

    item->ip_them   = parsed->src_ip;
    item->port_them = parsed->port_src;
    item->ip_me     = parsed->dst_ip;
    item->port_me   = parsed->port_dst;

    item->is_success = 1;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "open");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "udp reponse");

    /*theoretically, udp can take no data*/
    if (parsed->app_length) {
        if (UdpProbeScan.probe->handle_response_cb) {

            ipaddress ip_me    = parsed->dst_ip;
            ipaddress ip_them  = parsed->src_ip;
            unsigned port_me   = parsed->port_dst;
            unsigned port_them = parsed->port_src;

            UdpProbeScan.probe->handle_response_cb(
                ip_them, port_them, ip_me, port_me,
                port_me-src_port_start,
                &px[parsed->app_offset], parsed->app_length,
                item->report, OUTPUT_RPT_LEN);
        }
    }

    /*no reponse*/
    return 0;
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

    .make_packet_cb = &udpprobe_make_packet,

    .filter_packet_cb = &udpprobe_filter_packet,
    .validate_packet_cb = &udpprobe_validate_packet,
    .dedup_packet_cb = &udpprobe_dedup_packet,
    .handle_packet_cb = &udpprobe_handle_packet,
    .response_packet_cb = &scan_response_nothing,

    .close_cb = &scan_close_nothing,
};
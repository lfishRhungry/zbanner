#include <stdlib.h>

#include "scan-modules.h"
#include "../xconf.h"
#include "../stub/stub-pcap-dlt.h"
#include "../target/target-cookie.h"
#include "../templ/templ-udp.h"
#include "../templ/templ-icmp.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../util-out/logger.h"

extern Scanner UdpScan; /*for internal x-ref*/

struct UdpConf {
    unsigned record_banner   : 1;
    unsigned record_data     : 1;
    unsigned record_ttl      : 1;
    unsigned record_ipid     : 1;
    unsigned record_data_len : 1;
};

static struct UdpConf udp_conf = {0};

static ConfRes SET_record_data(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.record_data = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_banner(void *conf, const char *name,
                                 const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.record_banner = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_data_len(void *conf, const char *name,
                                   const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.record_data_len = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.record_ttl = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ipid(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.record_ipid = parse_str_bool(value);

    return Conf_OK;
}

static ConfParam udp_parameters[] = {
    {"record-banner",
     SET_record_banner,
     Type_FLAG,
     {"banner", 0},
     "Records banner content in escaped text style."},
    {"record-data",
     SET_record_data,
     Type_FLAG,
     {"data", 0},
     "Records data content in binary format."},
    {"record-ttl",
     SET_record_ttl,
     Type_FLAG,
     {"ttl", 0},
     "Records TTL for IPv4 or Hop Limit for IPv6."},
    {"record-ipid",
     SET_record_ipid,
     Type_FLAG,
     {"ipid", 0},
     "Records IPID just for IPv4."},
    {"record-data-len",
     SET_record_data_len,
     Type_FLAG,
     {"data-len", "len", 0},
     "Records payload data length."},

    {0}};

/**
 *For calc the conn index.
 * NOTE: We use a trick of src-port to differenciate multi-probes to avoid
 * mutual interference of connections.
 * Be careful to the source port range and probe num. Source port range is 256
 *in default and can be set with flag `--source-port`.
 */
static unsigned src_port_start;

static bool udp_init(const XConf *xconf) {
    src_port_start = xconf->nic.src.port.first;

    return true;
}

static bool udp_transmit(uint64_t entropy, ScanTarget *target,
                         unsigned char *px, size_t *len) {
    /*we just handle udp target*/
    if (target->target.ip_proto != IP_PROTO_UDP)
        return false;

    unsigned cookie = get_cookie(target->target.ip_them,
                                 target->target.port_them, target->target.ip_me,
                                 src_port_start + target->index, entropy);

    ProbeTarget ptarget = {
        .target.ip_proto  = target->target.ip_proto,
        .target.ip_them   = target->target.ip_them,
        .target.ip_me     = target->target.ip_me,
        .target.port_them = target->target.port_them,
        .target.port_me   = src_port_start + target->index,
        .cookie           = cookie,
        .index            = target->index,
    };

    unsigned char payload[PM_PAYLOAD_SIZE];
    size_t        payload_len = 0;

    payload_len = UdpScan.probe->make_payload_cb(&ptarget, payload);

    *len =
        udp_create_packet(target->target.ip_them, target->target.port_them,
                          target->target.ip_me, src_port_start + target->index,
                          0, payload, payload_len, px, PKT_BUF_SIZE);

    /*for multi-probe*/
    if (UdpScan.probe->multi_mode == Multi_Direct &&
        target->index + 1 < UdpScan.probe->multi_num)
        return true;
    else
        return false;
}

static void udp_validate(uint64_t entropy, Recved *recved, PreHandle *pre) {
    /*record packet to our source port*/
    if (recved->parsed.found == FOUND_UDP && recved->is_myip &&
        recved->is_myport) {
        pre->go_record = 1;

        ProbeTarget ptarget = {
            .target.ip_proto  = recved->parsed.ip_protocol,
            .target.ip_them   = recved->parsed.src_ip,
            .target.ip_me     = recved->parsed.dst_ip,
            .target.port_them = recved->parsed.port_src,
            .target.port_me   = recved->parsed.port_dst,
            .cookie = get_cookie(recved->parsed.src_ip, recved->parsed.port_src,
                                 recved->parsed.dst_ip, recved->parsed.port_dst,
                                 entropy),
            .index  = recved->parsed.port_dst - src_port_start,
        };

        if (UdpScan.probe->validate_response_cb(
                &ptarget, recved->packet + recved->parsed.app_offset,
                recved->parsed.app_length)) {
            pre->go_dedup = 1;
        }
    }
}

static void udp_handle(unsigned th_idx, uint64_t entropy, Recved *recved,
                       OutItem *item, STACK *stack) {
    ProbeTarget ptarget = {
        .target.ip_proto  = recved->parsed.ip_protocol,
        .target.ip_them   = recved->parsed.src_ip,
        .target.ip_me     = recved->parsed.dst_ip,
        .target.port_them = recved->parsed.port_src,
        .target.port_me   = recved->parsed.port_dst,
        .cookie =
            get_cookie(recved->parsed.src_ip, recved->parsed.port_src,
                       recved->parsed.dst_ip, recved->parsed.port_dst, entropy),
        .index = recved->parsed.port_dst - src_port_start,
    };

    unsigned is_multi = UdpScan.probe->handle_response_cb(
        th_idx, &ptarget, &recved->packet[recved->parsed.app_offset],
        recved->parsed.app_length, item);

    if (udp_conf.record_banner)
        dach_append_normalized(&item->report, "banner",
                               &recved->packet[recved->parsed.app_offset],
                               recved->parsed.app_length, LinkType_String);
    if (udp_conf.record_data)
        dach_append(&item->report, "data",
                    &recved->packet[recved->parsed.app_offset],
                    recved->parsed.app_length, LinkType_Binary);
    if (udp_conf.record_ttl)
        dach_set_int(&item->report, "ttl", recved->parsed.ip_ttl);
    if (udp_conf.record_ipid && recved->parsed.src_ip.version == 4)
        dach_set_int(&item->report, "ipid", recved->parsed.ip_v4_id);
    if (udp_conf.record_data_len) {
        dach_set_int(&item->report, "data len", recved->parsed.app_length);
    }

    /*for multi-probe Multi_AfterHandle*/
    if (UdpScan.probe->multi_mode == Multi_AfterHandle && is_multi &&
        recved->parsed.port_dst == src_port_start && UdpScan.probe->multi_num) {
        for (unsigned idx = 1; idx < UdpScan.probe->multi_num; idx++) {
            PktBuf *pkt_buffer = stack_get_pktbuf(stack);

            ProbeTarget ptarget = {
                .target.ip_proto  = recved->parsed.ip_protocol,
                .target.ip_them   = recved->parsed.src_ip,
                .target.ip_me     = recved->parsed.dst_ip,
                .target.port_them = recved->parsed.port_src,
                .target.port_me   = src_port_start + idx,
                .cookie           = get_cookie(
                    recved->parsed.src_ip, recved->parsed.port_src,
                    recved->parsed.dst_ip, src_port_start + idx, entropy),
                .index = idx,
            };

            unsigned char payload[PM_PAYLOAD_SIZE];
            size_t        payload_len = 0;

            payload_len = UdpScan.probe->make_payload_cb(&ptarget, payload);

            pkt_buffer->length = udp_create_packet(
                recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, src_port_start + idx, 0, payload,
                payload_len, pkt_buffer->px, PKT_BUF_SIZE);

            stack_transmit_pktbuf(stack, pkt_buffer);
        }

        return;
    }

    /*for multi-probe Multi_DynamicNext*/
    if (UdpScan.probe->multi_mode == Multi_DynamicNext && is_multi) {
        PktBuf *pkt_buffer = stack_get_pktbuf(stack);

        ProbeTarget ptarget = {
            .target.ip_proto  = recved->parsed.ip_protocol,
            .target.ip_them   = recved->parsed.src_ip,
            .target.ip_me     = recved->parsed.dst_ip,
            .target.port_them = recved->parsed.port_src,
            .target.port_me   = src_port_start + is_multi - 1,
            .cookie = get_cookie(recved->parsed.src_ip, recved->parsed.port_src,
                                 recved->parsed.dst_ip,
                                 src_port_start + is_multi - 1, entropy),
            .index  = is_multi - 1,
        };

        unsigned char payload[PM_PAYLOAD_SIZE];
        size_t        payload_len = 0;

        payload_len = UdpScan.probe->make_payload_cb(&ptarget, payload);

        pkt_buffer->length = udp_create_packet(
            recved->parsed.src_ip, recved->parsed.port_src,
            recved->parsed.dst_ip, src_port_start + is_multi - 1, 0, payload,
            payload_len, pkt_buffer->px, PKT_BUF_SIZE);

        stack_transmit_pktbuf(stack, pkt_buffer);

        return;
    }
}

Scanner UdpScan = {
    .name                = "udp",
    .required_probe_type = ProbeType_UDP,
    .params              = udp_parameters,
    /*udp and icmp port unreachable in ipv4 & ipv6*/
    .bpf_filter          = "udp",
    .short_desc          = "Single-packet UDP scan with specified ProbeModule.",
    .desc =
        "UdpScan sends a udp packet with ProbeModule data to target port "
        "and expects a udp response to believe the port is open or an icmp "
        "port "
        "unreachable message if closed. Responsed data will be processed and "
        "formed a report by ProbeModule.\n"
        "UdpScan prefer the first reponse udp packet. But all packets to us "
        "could be record to pcap file.\n"
        "NOTE: Our host may send an ICMP Port Unreachable message to target "
        "after"
        " received udp response because we send udp packets bypassing the "
        "protocol"
        " stack of OS. Sometimes it can cause problems or needless "
        "retransmission"
        " from server side. We could add iptables rules displayed in "
        "`firewall` "
        "directory to ban this. Or we could observe some strange things.",

    .init_cb     = &udp_init,
    .transmit_cb = &udp_transmit,
    .validate_cb = &udp_validate,
    .handle_cb   = &udp_handle,
    .poll_cb     = &scan_poll_nothing,
    .close_cb    = &scan_close_nothing,
    .status_cb   = &scan_no_status,
};
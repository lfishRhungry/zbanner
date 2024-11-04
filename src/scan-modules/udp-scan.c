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

static const TargetSet *_targets = NULL;

struct UdpConf {
    unsigned record_banner       : 1;
    unsigned record_utf8         : 1;
    unsigned record_data         : 1;
    unsigned record_ttl          : 1;
    unsigned record_ipid         : 1;
    unsigned record_data_len     : 1;
    unsigned record_icmp_id      : 1;
    unsigned record_icmp_seqno   : 1;
    unsigned record_icmp_ip_them : 1;
    unsigned record_icmp_ip_me   : 1;
    unsigned no_port_unreachable : 1;
    unsigned is_port_failure     : 1;
    unsigned no_pre_validate     : 1;
    unsigned repeat_packet       : 1;
};

static struct UdpConf udp_conf = {0};

static ConfRes SET_repeat_packet(void *conf, const char *name,
                                 const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.repeat_packet = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_no_pre_validate(void *conf, const char *name,
                                   const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.no_pre_validate = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_icmp_ip_them(void *conf, const char *name,
                                       const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.record_icmp_ip_them = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_icmp_ip_me(void *conf, const char *name,
                                     const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.record_icmp_ip_me = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_icmp_seqno(void *conf, const char *name,
                                     const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.record_icmp_seqno = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_icmp_id(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.record_icmp_id = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_port_failure(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.is_port_failure = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_no_port_unreachable(void *conf, const char *name,
                                       const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.no_port_unreachable = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_data(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.record_data = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_utf8(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    udp_conf.record_utf8 = parse_str_bool(value);

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
     "Records banner content in escaped text style. Banner is also valid for "
     "ICMP port unreachable, it means internal IP header plus some original "
     "data of datagram."},
    {"record-utf8",
     SET_record_utf8,
     Type_FLAG,
     {"utf8", 0},
     "Records banner content with escaped valid utf8 encoding."},
    {"record-data",
     SET_record_data,
     Type_FLAG,
     {"data", 0},
     "Records data content in binary format. Data is also valid for ICMP port "
     "unreachable, it means internal IP header plus some original data of "
     "datagram."},
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
     "Records payload data length. Data length is also valid for ICMP port "
     "unreachable, it means length of internal IP header plus some original "
     "data of datagram."},
    {"record-icmp-id",
     SET_record_icmp_id,
     Type_FLAG,
     {"icmp-id", 0},
     "Records ICMP identifier number of port unreachable messages."},
    {"record-icmp-seqno",
     SET_record_icmp_seqno,
     Type_FLAG,
     {"icmp-seqno", 0},
     "Records ICMP sequence number of port unreachable messages."},
    {"record-icmp-ip-them",
     SET_record_icmp_ip_them,
     Type_FLAG,
     {"icmp-ip-them", 0},
     "Records target IP in ICMP port unreachable messages. It can be different "
     "from the outside target IP sometimes."},
    {"record-icmp-ip-me",
     SET_record_icmp_ip_me,
     Type_FLAG,
     {"icmp-ip-me", 0},
     "Records source IP in ICMP port unreachable messages. It can be different "
     "from the outside source IP sometimes."},
    {"no-port-unreachable",
     SET_no_port_unreachable,
     Type_FLAG,
     {"no-icmp", "no-closed", "no-close", 0},
     "Do not care ICMP port unreachable for target port. UdpScan would check "
     "ICMP port unreachable by target range while using default generator. "
     "This checking could be inaccurate in some extreme cases."},
    {"no-pre-validate",
     SET_no_pre_validate,
     Type_FLAG,
     {0},
     "Do not use target range containing as connection pre-validation.\n"
     "NOTE: Some probes do not have own validation and rely on it."},
    {"port-failure",
     SET_port_failure,
     Type_FLAG,
     {"failure-port", "port-fail", "fail-port", 0},
     "Let port closed results as failure level.(Default is info level)"},
    {"repeat-packets",
     SET_repeat_packet,
     Type_FLAG,
     {"repeat-packet", "repeat", 0},
     "Allow repeated packets."},

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

    if (strcmp(xconf->generator->name, "blackrock") == 0) {
        _targets = &xconf->targets;
    } else {
        LOG(LEVEL_WARN,
            "use non-default generator so that cannot do pre-validation and "
            "get ICMP port unreachable results.\n");
    }

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

        /**
         * pre-validate by target range
         */
        if (_targets && !udp_conf.no_pre_validate) {
            if (targetset_has_ip(_targets, recved->parsed.src_ip) &&
                targetset_has_port(
                    _targets,
                    get_complex_port(recved->parsed.port_src, IP_PROTO_UDP)))
                ;
            else
                return;
        }

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

        return;
    }

    /*handle ICMP port unreachable by target set*/
    if (_targets == NULL || udp_conf.no_port_unreachable)
        return;

    if (recved->parsed.found != FOUND_ICMP || !recved->is_myip) {
        return;
    }

    if (recved->parsed.dst_ip.version == 4 &&
        recved->parsed.icmp_type == ICMPv4_TYPE_ERR &&
        recved->parsed.icmp_code == ICMPv4_CODE_ERR_PORT_UNREACHABLE) {
        ;
    } else if (recved->parsed.dst_ip.version == 6 &&
               recved->parsed.icmp_type == ICMPv6_TYPE_ERR &&
               recved->parsed.icmp_code == ICMPv6_CODE_ERR_PORT_UNREACHABLE) {
        ;
    } else {
        return;
    }

    /*parse UDP packet in ICMP port unreachable message payload*/
    unsigned  icmp_proto = IP_PROTO_Other;
    ipaddress icmp_ip_them;
    ipaddress icmp_ip_me;
    /**
     * NOTE: just replace the ports for deduplication. IPs in ICMP payload can
     * not be our original target sometimes.
     */
    if (parse_icmp_port_unreachable(
            recved->packet + recved->parsed.transport_offset,
            recved->parsed.transport_length, &icmp_ip_them,
            &pre->dedup_port_them, &icmp_ip_me, &pre->dedup_port_me,
            &icmp_proto)) {
        if (icmp_proto == IP_PROTO_UDP &&
            targetset_has_ip(_targets, pre->dedup_ip_them) &&
            targetset_has_port(_targets, get_complex_port(pre->dedup_port_them,
                                                          IP_PROTO_UDP))) {
            pre->go_record = 1;
            pre->go_dedup  = 1;
        }
    }
}

static void udp_handle(unsigned th_idx, uint64_t entropy,
                       ValidPacket *valid_pkt, OutItem *item, STACK *stack) {
    if (!udp_conf.repeat_packet && valid_pkt->repeats) {
        item->no_output = 1;
        return;
    } else if (udp_conf.repeat_packet) {
        dach_set_int(&item->report, "repeats", valid_pkt->repeats);
    }
    Recved *recved = &valid_pkt->recved;

    if (recved->parsed.found == FOUND_UDP) {
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

        unsigned is_multi = UdpScan.probe->handle_response_cb(
            th_idx, &ptarget, &recved->packet[recved->parsed.app_offset],
            recved->parsed.app_length, item);

        /*for multi-probe Multi_AfterHandle*/
        if (UdpScan.probe->multi_mode == Multi_AfterHandle && is_multi &&
            recved->parsed.port_dst == src_port_start &&
            UdpScan.probe->multi_num) {
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
                .cookie =
                    get_cookie(recved->parsed.src_ip, recved->parsed.port_src,
                               recved->parsed.dst_ip,
                               src_port_start + is_multi - 1, entropy),
                .index = is_multi - 1,
            };

            unsigned char payload[PM_PAYLOAD_SIZE];
            size_t        payload_len = 0;

            payload_len = UdpScan.probe->make_payload_cb(&ptarget, payload);

            pkt_buffer->length = udp_create_packet(
                recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, src_port_start + is_multi - 1, 0,
                payload, payload_len, pkt_buffer->px, PKT_BUF_SIZE);

            stack_transmit_pktbuf(stack, pkt_buffer);
        }
    } else { /*ICMP port unreachable*/

        /**
         * I'm not sure if the output ip proto should be UDP or ICMP
         */
        unsigned  icmp_proto = IP_PROTO_Other;
        ipaddress icmp_ip_them;
        ipaddress icmp_ip_me;
        /**
         * NOTE: Do not replace the IPs of output item. IPs in ICMP payload can
         * not be our original target sometimes.
         */
        parse_icmp_port_unreachable(
            recved->packet + recved->parsed.transport_offset,
            recved->parsed.transport_length, &icmp_ip_them,
            &item->target.port_them, &icmp_ip_me, &item->target.port_me,
            &icmp_proto);

        if (udp_conf.is_port_failure)
            item->level = OUT_FAILURE;

        item->no_port = 1;

        safe_strcpy(item->classification, OUT_CLS_SIZE, "closed");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "port unreachable");

        if (udp_conf.record_icmp_id)
            dach_set_int(&item->report, "icmp id", recved->parsed.icmp_id);
        if (udp_conf.record_icmp_seqno)
            dach_set_int(&item->report, "icmp seqno",
                         recved->parsed.icmp_seqno);

        const char *icmp_proto_str = ip_proto_to_string(icmp_proto);
        dach_set_int(&item->report, "icmp port_me", item->target.port_me);
        if (udp_conf.record_icmp_ip_me) {
            ipaddress_formatted_t icmp_ip_me_fmt = ipaddress_fmt(icmp_ip_me);
            dach_append(&item->report, "icmp ip_me", icmp_ip_me_fmt.string,
                        strlen(icmp_ip_me_fmt.string), LinkType_String);
        }
        dach_set_int(&item->report, "icmp port_them", item->target.port_them);
        if (udp_conf.record_icmp_ip_them) {
            ipaddress_formatted_t icmp_ip_them_fmt =
                ipaddress_fmt(icmp_ip_them);
            dach_append(&item->report, "icmp ip_them", icmp_ip_them_fmt.string,
                        strlen(icmp_ip_them_fmt.string), LinkType_String);
        }
        dach_append(&item->report, "icmp proto", icmp_proto_str,
                    strlen(icmp_proto_str), LinkType_String);
    }

    if (udp_conf.record_ttl)
        dach_set_int(&item->report, "ttl", recved->parsed.ip_ttl);
    if (udp_conf.record_ipid && recved->parsed.src_ip.version == 4)
        dach_set_int(&item->report, "ipid", recved->parsed.ip_v4_id);
    if (udp_conf.record_data_len) {
        dach_set_int(&item->report, "data len", recved->parsed.app_length);
    }
    if (udp_conf.record_data)
        dach_append(&item->report, "data",
                    &recved->packet[recved->parsed.app_offset],
                    recved->parsed.app_length, LinkType_Binary);
    if (udp_conf.record_utf8)
        dach_append_utf8(&item->report, "utf8",
                         &recved->packet[recved->parsed.app_offset],
                         recved->parsed.app_length, LinkType_String);
    if (udp_conf.record_banner)
        dach_append_banner(&item->report, "banner",
                           &recved->packet[recved->parsed.app_offset],
                           recved->parsed.app_length, LinkType_String);
}

Scanner UdpScan = {
    .name                = "udp",
    .required_probe_type = ProbeType_UDP,
    .params              = udp_parameters,
    /*udp and icmp port unreachable in ipv4 & ipv6*/
    .bpf_filter = "udp || (icmp && icmp[0]=3 && icmp[1]=3) || (icmp6 && "
                  "icmp6[0]=1 && icmp6[1]=4)",
    .short_desc = "Single-packet UDP scan with specified ProbeModule.",
    .desc = "UdpScan sends a udp packet with ProbeModule data to target port "
            "and expects a udp response to believe the port is open or an icmp "
            "port unreachable message if closed. Responsed data will be "
            "processed and formed a report by ProbeModule.\n"
            "NOTE1: Our host may send an ICMP Port Unreachable message to "
            "target after received udp response because we send udp packets "
            "bypassing the protocol stack of OS. Sometimes it can cause "
            "problems or needless retransmission from server side. We could "
            "add iptables rules displayed in `firewall` directory to ban this. "
            "Or we could observe some strange things.\n"
            "NOTE2: udp is stateless by itself so there's no connection "
            "validation from protocol level. UdpScan uses target range "
            "containing as pre-validation if uses default generator. Some udp "
            "type probes can have their own validations.",

    .init_cb     = &udp_init,
    .transmit_cb = &udp_transmit,
    .validate_cb = &udp_validate,
    .handle_cb   = &udp_handle,
    .poll_cb     = &scan_poll_nothing,
    .close_cb    = &scan_close_nothing,
    .status_cb   = &scan_no_status,
};
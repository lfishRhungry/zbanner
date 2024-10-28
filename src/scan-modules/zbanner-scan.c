#include <stdlib.h>

#include "scan-modules.h"
#include "../xconf.h"
#include "../target/target-cookie.h"
#include "../templ/templ-tcp.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../util-out/logger.h"

extern Scanner ZBannerScan; /*for internal x-ref*/

struct ZBannerConf {
    uint8_t  syn_ttl;
    uint8_t  ack_ttl;
    uint8_t  rst_ttl;
    uint8_t  probe_ttl;
    unsigned is_port_success : 1;
    unsigned is_port_failure : 1;
    unsigned record_ttl      : 1;
    unsigned record_ipid     : 1;
    unsigned record_win      : 1;
    unsigned record_mss      : 1;
    unsigned record_seq      : 1;
    unsigned record_ack      : 1;
    unsigned with_ack        : 1;
    unsigned no_rst          : 1;
};

static struct ZBannerConf zbanner_conf = {0};

static ConfRes SET_record_ack(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_ack = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_seq(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_seq = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_probe_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.probe_ttl = parse_str_int(value);

    return Conf_OK;
}

static ConfRes SET_rst_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.rst_ttl = parse_str_int(value);

    return Conf_OK;
}

static ConfRes SET_ack_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.ack_ttl = parse_str_int(value);

    return Conf_OK;
}

static ConfRes SET_syn_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.syn_ttl = parse_str_int(value);

    return Conf_OK;
}

static ConfRes SET_no_rst(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.no_rst = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_with_ack(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.with_ack = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_mss(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_mss = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_ttl = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ipid(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_ipid = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_win(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_win = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_port_success(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.is_port_success = parse_str_bool(value);

    return Conf_OK;
}

static ConfRes SET_port_failure(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.is_port_failure = parse_str_bool(value);

    return Conf_OK;
}

static ConfParam zbanner_parameters[] = {
    {"port-success",
     SET_port_success,
     Type_FLAG,
     {"success-port", 0},
     "Let port opening(contains zero syn-ack) results as success level."
     "(Default is info level)"},
    {"port-failure",
     SET_port_failure,
     Type_FLAG,
     {"failure-port", "port-fail", "fail-port", 0},
     "Let port closed results as failure level.(Default is info level)"},
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
    {"record-win",
     SET_record_win,
     Type_FLAG,
     {"win", "window", 0},
     "Records TCP window size of SYN-ACK or RST."},
    {"record-mss",
     SET_record_mss,
     Type_FLAG,
     {"mss", 0},
     "Records TCP MSS option value of SYN-ACK if the option exists."},
    {"record-seq",
     SET_record_seq,
     Type_FLAG,
     {"seq", 0},
     "Records TCP sequence number."},
    {"record-ack",
     SET_record_ack,
     Type_FLAG,
     {"ack", 0},
     "Records TCP acknowledge number."},
    {"with-ack",
     SET_with_ack,
     Type_FLAG,
     {0},
     "Send an seperate ACK segment after receiving non-zerowin SYNACK segment "
     "from target port. This makes a complete standard TCP 3-way handshake "
     "before sending segment with data(probe) and spends more bandwidth while "
     "scanning. But some servers(not very sure) may only accept this kind of "
     "connections. However, it's the early version of ZBanner and can also be "
     "used for research."},
    {"no-rst",
     SET_no_rst,
     Type_FLAG,
     {0},
     "Do not send RST segment after got banner. It's used for research."},
    {"syn-ttl",
     SET_syn_ttl,
     Type_ARG,
     {0},
     "Set TTL of SYN segment to specified value instead of global default."},
    {"ack-ttl",
     SET_ack_ttl,
     Type_ARG,
     {0},
     "Set TTL of ACK segment during 3-way handshake to specified value instead "
     "of global default."},
    {"rst-ttl",
     SET_rst_ttl,
     Type_ARG,
     {0},
     "Set TTL of RST segment to specified value instead of global default."},
    {"probe-ttl",
     SET_probe_ttl,
     Type_ARG,
     {0},
     "Set TTL of ACK segment with probe data to specified value instead of "
     "global default."},

    {0}};

/**
 *For calc the conn index.
 * NOTE: We use a trick of src-port to differenciate multi-probes to avoid
 * mutual interference of connections.
 * Be careful to the source port range and probe num. Source port range is 256
 *in default and can be set with flag `--source-port`.
 */
static unsigned src_port_start;

static bool zbanner_init(const XConf *xconf) {
    src_port_start = xconf->nic.src.port.first;

    return true;
}

static bool zbanner_transmit(uint64_t entropy, ScanTarget *target,
                             unsigned char *px, size_t *len) {
    /*we just handle tcp target*/
    if (target->target.ip_proto != IP_PROTO_TCP)
        return false;

    unsigned seqno = get_cookie(target->target.ip_them,
                                target->target.port_them, target->target.ip_me,
                                src_port_start + target->index, entropy);

    *len = tcp_create_packet(
        target->target.ip_them, target->target.port_them, target->target.ip_me,
        src_port_start + target->index, seqno, 0, TCP_FLAG_SYN,
        zbanner_conf.syn_ttl, 0, NULL, 0, px, PKT_BUF_SIZE);

    /*multi-probe Multi_Direct*/
    if (ZBannerScan.probe->multi_mode == Multi_Direct &&
        target->index + 1 < ZBannerScan.probe->multi_num)
        return true;

    return false;
}

static void zbanner_validate(uint64_t entropy, Recved *recved, PreHandle *pre) {
    if (recved->parsed.found == FOUND_TCP && recved->is_myip &&
        recved->is_myport)
        pre->go_record = 1;
    else
        return;

    unsigned seqno_me =
        TCP_ACKNO(recved->packet, recved->parsed.transport_offset);
    unsigned cookie =
        get_cookie(recved->parsed.src_ip, recved->parsed.port_src,
                   recved->parsed.dst_ip, recved->parsed.port_dst, entropy);

    /*syn-ack*/
    if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
                     TCP_FLAG_SYN | TCP_FLAG_ACK)) {
        if (cookie == seqno_me - 1) {
            pre->go_dedup   = 1;
            pre->dedup_type = 0;
        }
    }
    /*
    * First packet with reponsed banner data.

    * We could recv Response DATA with some combinations of TCP flags
    * 1.[ACK]: maybe more data
    * 2.[PSH, ACK]: no more data
    * 3.[FIN, PSH, ACK]: no more data and disconnecting
    */
    else if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
                          TCP_FLAG_ACK) &&
             recved->parsed.app_length) {
        ProbeTarget ptarget = {
            .target.ip_proto  = recved->parsed.ip_protocol,
            .target.ip_them   = recved->parsed.src_ip,
            .target.ip_me     = recved->parsed.dst_ip,
            .target.port_them = recved->parsed.port_src,
            .target.port_me   = recved->parsed.port_dst,
            .cookie           = 0, /*zbanner can recognize reponse by itself*/
            .index            = recved->parsed.port_dst - src_port_start,
        };

        size_t payload_len;
        payload_len = ZBannerScan.probe->get_payload_length_cb(&ptarget);

        if (seqno_me == cookie + payload_len + 1) {
            pre->go_dedup   = 1;
            pre->dedup_type = 1;
        }
    }
    /*rst for syn (a little different)*/
    else if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
                          TCP_FLAG_RST)) {
        if (seqno_me == cookie + 1 || seqno_me == cookie) {
            pre->go_dedup   = 1;
            pre->dedup_type = 0;
        }
    }
}

static void zbanner_handle(unsigned th_idx, uint64_t entropy, Recved *recved,
                           OutItem *item, STACK *stack) {
    unsigned mss_them;
    bool     mss_found;
    uint16_t win_them;

    unsigned seqno_me =
        TCP_ACKNO(recved->packet, recved->parsed.transport_offset);
    unsigned seqno_them =
        TCP_SEQNO(recved->packet, recved->parsed.transport_offset);

    /*SYNACK*/
    if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
                     TCP_FLAG_SYN | TCP_FLAG_ACK)) {
        /*zerowin could be a kind of port open*/
        if (zbanner_conf.is_port_success) {
            item->level = OUT_SUCCESS;
        }

        win_them = TCP_WIN(recved->packet, recved->parsed.transport_offset);

        if (zbanner_conf.record_ttl)
            dach_set_int(&item->report, "ttl", recved->parsed.ip_ttl);
        if (zbanner_conf.record_ipid && recved->parsed.src_ip.version == 4)
            dach_set_int(&item->report, "ipid", recved->parsed.ip_v4_id);
        if (zbanner_conf.record_win)
            dach_set_int(&item->report, "win", win_them);
        if (zbanner_conf.record_mss) {
            /*comput of mss is not easy*/
            mss_them = tcp_get_mss(recved->packet, recved->length, &mss_found);
            if (!mss_found)
                mss_them = 0;
            dach_set_int(&item->report, "mss", mss_them);
        }
        if (zbanner_conf.record_seq) {
            dach_set_int(&item->report, "seq", seqno_them);
        }
        if (zbanner_conf.record_ack) {
            dach_set_int(&item->report, "ack", seqno_me);
        }

        if (win_them == 0) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "fake-open");
            safe_strcpy(item->reason, OUT_RSN_SIZE, "zerowin");
        } else {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "open");
            safe_strcpy(item->reason, OUT_RSN_SIZE, "syn-ack");

            /*stack(send) ack with probe*/
            ProbeTarget ptarget = {
                .target.ip_proto  = recved->parsed.ip_protocol,
                .target.ip_them   = recved->parsed.src_ip,
                .target.ip_me     = recved->parsed.dst_ip,
                .target.port_them = recved->parsed.port_src,
                .target.port_me   = recved->parsed.port_dst,
                /*zbanner can recognize reponse by itself*/
                .cookie           = 0,
                .index            = recved->parsed.port_dst - src_port_start,
            };

            unsigned char payload[PM_PAYLOAD_SIZE];
            size_t        payload_len = 0;

            payload_len = ZBannerScan.probe->make_payload_cb(&ptarget, payload);

            /**
             * Use a complete standard TCP 3-way handshake
             */
            if (payload_len > 0 && zbanner_conf.with_ack) {
                PktBuf *pkt_buffer_ack = stack_get_pktbuf(stack);

                pkt_buffer_ack->length = tcp_create_packet(
                    recved->parsed.src_ip, recved->parsed.port_src,
                    recved->parsed.dst_ip, recved->parsed.port_dst, seqno_me,
                    seqno_them + 1, TCP_FLAG_ACK, zbanner_conf.ack_ttl, 0, NULL,
                    0, pkt_buffer_ack->px, PKT_BUF_SIZE);

                stack_transmit_pktbuf(stack, pkt_buffer_ack);
            }

            PktBuf *pkt_buffer = stack_get_pktbuf(stack);

            pkt_buffer->length = tcp_create_packet(
                recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, recved->parsed.port_dst, seqno_me,
                seqno_them + 1, TCP_FLAG_ACK, zbanner_conf.probe_ttl, 0,
                payload, payload_len, pkt_buffer->px, PKT_BUF_SIZE);

            stack_transmit_pktbuf(stack, pkt_buffer);

            /*multi-probe Multi_IfOpen*/
            if (ZBannerScan.probe->multi_mode == Multi_IfOpen &&
                recved->parsed.port_dst == src_port_start) {
                for (unsigned idx = 1; idx < ZBannerScan.probe->multi_num;
                     idx++) {
                    unsigned cookie = get_cookie(
                        recved->parsed.src_ip, recved->parsed.port_src,
                        recved->parsed.dst_ip, src_port_start + idx, entropy);

                    PktBuf *pkt_buffer = stack_get_pktbuf(stack);

                    pkt_buffer->length = tcp_create_packet(
                        recved->parsed.src_ip, recved->parsed.port_src,
                        recved->parsed.dst_ip, src_port_start + idx, cookie, 0,
                        TCP_FLAG_SYN, zbanner_conf.syn_ttl, 0, NULL, 0,
                        pkt_buffer->px, PKT_BUF_SIZE);

                    stack_transmit_pktbuf(stack, pkt_buffer);
                }
            }
        }
    }
    /*RST*/
    else if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
                          TCP_FLAG_RST)) {
        win_them = TCP_WIN(recved->packet, recved->parsed.transport_offset);

        if (zbanner_conf.record_ttl)
            dach_set_int(&item->report, "ttl", recved->parsed.ip_ttl);
        if (zbanner_conf.record_ipid && recved->parsed.src_ip.version == 4)
            dach_set_int(&item->report, "ipid", recved->parsed.ip_v4_id);
        if (zbanner_conf.record_win)
            dach_set_int(&item->report, "win", win_them);
        if (zbanner_conf.record_seq) {
            dach_set_int(&item->report, "seq", seqno_them);
        }
        if (zbanner_conf.record_ack) {
            dach_set_int(&item->report, "ack", seqno_me);
        }

        safe_strcpy(item->reason, OUT_RSN_SIZE, "rst");
        safe_strcpy(item->classification, OUT_CLS_SIZE, "closed");

        if (zbanner_conf.is_port_failure) {
            item->level = OUT_FAILURE;
        }
    }
    /*Banner*/
    else {
        /*send rst first to disconn*/
        if (!zbanner_conf.no_rst) {
            PktBuf *pkt_buffer = stack_get_pktbuf(stack);

            pkt_buffer->length = tcp_create_packet(
                recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, recved->parsed.port_dst, seqno_me,
                seqno_them + 1, TCP_FLAG_RST, zbanner_conf.rst_ttl, 0, NULL, 0,
                pkt_buffer->px, PKT_BUF_SIZE);

            stack_transmit_pktbuf(stack, pkt_buffer);
        }

        ProbeTarget ptarget = {
            .target.ip_proto  = recved->parsed.ip_protocol,
            .target.ip_them   = recved->parsed.src_ip,
            .target.ip_me     = recved->parsed.dst_ip,
            .target.port_them = recved->parsed.port_src,
            .target.port_me   = recved->parsed.port_dst,
            .cookie           = 0, /*zbanner can recognize reponse by itself*/
            .index            = recved->parsed.port_dst - src_port_start,
        };

        unsigned is_multi = ZBannerScan.probe->handle_response_cb(
            th_idx, &ptarget, &recved->packet[recved->parsed.app_offset],
            recved->parsed.app_length, item);

        /*ttl and ipid is also impportant for non-synack segment*/
        if (zbanner_conf.record_ttl)
            dach_set_int(&item->report, "ttl", recved->parsed.ip_ttl);
        if (zbanner_conf.record_ipid && recved->parsed.src_ip.version == 4)
            dach_set_int(&item->report, "ipid", recved->parsed.ip_v4_id);
        if (zbanner_conf.record_seq) {
            dach_set_int(&item->report, "seq", seqno_them);
        }
        if (zbanner_conf.record_ack) {
            dach_set_int(&item->report, "ack", seqno_me);
        }

        /*multi-probe Multi_AfterHandle*/
        if (ZBannerScan.probe->multi_mode == Multi_AfterHandle && is_multi &&
            recved->parsed.port_dst == src_port_start) {
            for (unsigned idx = 1; idx < ZBannerScan.probe->multi_num; idx++) {
                unsigned cookie = get_cookie(
                    recved->parsed.src_ip, recved->parsed.port_src,
                    recved->parsed.dst_ip, src_port_start + idx, entropy);

                PktBuf *pkt_buffer = stack_get_pktbuf(stack);

                pkt_buffer->length = tcp_create_packet(
                    recved->parsed.src_ip, recved->parsed.port_src,
                    recved->parsed.dst_ip, src_port_start + idx, cookie, 0,
                    TCP_FLAG_SYN, zbanner_conf.syn_ttl, 0, NULL, 0,
                    pkt_buffer->px, PKT_BUF_SIZE);

                stack_transmit_pktbuf(stack, pkt_buffer);
            }

            return;
        }

        /*multi-probe Multi_DynamicNext*/
        if (ZBannerScan.probe->multi_mode == Multi_DynamicNext && is_multi) {
            unsigned cookie = get_cookie(
                recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, src_port_start + is_multi - 1, entropy);

            PktBuf *pkt_buffer = stack_get_pktbuf(stack);

            pkt_buffer->length = tcp_create_packet(
                recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, src_port_start + is_multi - 1, cookie, 0,
                TCP_FLAG_SYN, zbanner_conf.syn_ttl, 0, NULL, 0, pkt_buffer->px,
                PKT_BUF_SIZE);

            stack_transmit_pktbuf(stack, pkt_buffer);
        }
    }
}

Scanner ZBannerScan = {
    .name                = "zbanner",
    .required_probe_type = ProbeType_TCP,
    .params              = zbanner_parameters,
    /*is rst or with ack in ipv4 & ipv6*/
    .bpf_filter =
        "(ip && tcp && (tcp[tcpflags]|tcp-ack!=0 || tcp[tcpflags]==tcp-rst)) "
        "|| (ip6 && tcp && (ip6[40+13]|tcp-ack!=0 || ip6[40+13]==tcp-rst))",
    .short_desc = "Stateless TCP scan with specified ProbeModule.",
    .desc =
        "ZBannerScan tries to contruct TCP conn with target port and send data "
        "from specified ProbeModule. Data in first reponse packet will be "
        "handled by specified ProbeModule.\n"
        "What important is the whole process was done in completely stateless. "
        "So ZBannerScan is very fast for large-scale probing like banner "
        "grabbing, service identification and etc.\n"
        "By the way, ZBanner support `timeout` just for banner response and "
        "port openness(syn-ack).\n"
        "NOTE1: Must specify a TcpType ProbeModule for ZBannerScan like:\n"
        "    `--probe-module xxx`\n"
        "NOTE2: ZBannerScan will construct complete TCP conns. So must avoid "
        "Linux system sending RST automatically by adding iptable rules "
        "displayed in `firewall` directory.\n"
        "NOTE3: Slow send rate may cause target host's retransmition.",

    .init_cb     = &zbanner_init,
    .transmit_cb = &zbanner_transmit,
    .validate_cb = &zbanner_validate,
    .handle_cb   = &zbanner_handle,
    .poll_cb     = &scan_poll_nothing,
    .close_cb    = &scan_close_nothing,
    .status_cb   = &scan_no_status,
};
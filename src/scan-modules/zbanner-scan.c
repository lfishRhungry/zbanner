#include <stdlib.h>

#include "scan-modules.h"
#include "../xconf.h"
#include "../cookie.h"
#include "../templ/templ-tcp.h"
#include "../util/mas-safefunc.h"
#include "../util/mas-malloc.h"
#include "../util/logger.h"

extern struct ScanModule ZBannerScan; /*for internal x-ref*/

/**
 *For calc the conn index.
 * NOTE: We use a trick of src-port to differenciate multi-probes to avoid
 * mutual interference of connections.
 * Be careful to the source port range and probe num. Source port range is 16 in
 * default and can be set with flag `--source-port`.
*/
static unsigned src_port_start;

static int
zbanner_global_init(const void *xconf)
{
    if (!ZBannerScan.probe) {
        LOG(0, "FAIL: ZBannerScan needs a specified tcp ProbeModule.\n");
        LOG(0, "    Hint: specify ProbeModule like `--probe-module null`.\n");
        return 0;
    }

    if (ZBannerScan.probe->type != ProbeType_TCP) {
        LOG(0, "FAIL: ZBannerScan needs a tcp type ProbeModule.\n");
        LOG(0, "    Current ProbeModule %s is %s type.\n",
            ZBannerScan.probe->name, get_probe_type_name(ZBannerScan.probe->type));
        return 0;
    }

    src_port_start = ((const struct Xconf *)xconf)->nic.src.port.first;

    return 1;
}

static int
zbanner_transmit_packet(
    uint64_t entropy,
    struct ScanTarget *target,
    unsigned char *px, size_t *len)
{
    /*we just handle tcp target*/
    if (target->proto != Proto_TCP)
        return 0;

    /*`index` is unused now*/
    unsigned seqno = get_cookie(target->ip_them, target->port_them, target->ip_me,
        src_port_start, entropy);

    *len = tcp_create_packet(
        target->ip_them, target->port_them, target->ip_me, src_port_start,
        seqno, 0, TCP_FLAG_SYN, NULL, 0, px, PKT_BUF_LEN);
    
    return 0;
}

static void
zbanner_validate(
    uint64_t entropy,
    struct Received *recved,
    struct PreHandle *pre)
{
    if (recved->parsed.found == FOUND_TCP
        && recved->is_myip
        && recved->is_myport)
        pre->go_record = 1;
    else return;

    ipaddress ip_them  = recved->parsed.src_ip;
    ipaddress ip_me    = recved->parsed.dst_ip;
    unsigned port_them = recved->parsed.port_src;
    unsigned port_me   = recved->parsed.port_dst;
    unsigned seqno_me  = TCP_ACKNO(recved->packet, recved->parsed.transport_offset);
    unsigned cookie    = get_cookie(ip_them, port_them, ip_me, port_me, entropy);


    /*syn-ack*/
    if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
        TCP_FLAG_SYN|TCP_FLAG_ACK)) {
        if (cookie == seqno_me - 1) {
            pre->go_dedup = 1;
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
    else if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset, TCP_FLAG_ACK)
        && recved->parsed.app_length) {
        size_t payload_len;
        payload_len = ZBannerScan.probe->get_payload_length_cb(
            ip_them, port_them, ip_me, port_me, cookie, port_me-src_port_start);
        if (seqno_me == cookie + payload_len + 1) {
            pre->go_dedup = 1;
            pre->dedup_type = 1;
        }
    }
    /*rst for syn (a little different)*/
    else if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
        TCP_FLAG_RST)) {
        if (seqno_me == cookie + 1 || seqno_me == cookie) {
            pre->go_dedup = 1;
            pre->dedup_type = 0;
        }
    }
}

static void
zbanner_handle(
    uint64_t entropy,
    struct Received *recved,
    struct OutputItem *item,
    struct stack_t *stack)
{
    ipaddress ip_them   = recved->parsed.src_ip;
    ipaddress ip_me     = recved->parsed.dst_ip;
    unsigned port_them  = recved->parsed.port_src;
    unsigned port_me    = recved->parsed.port_dst;
    unsigned seqno_me   = TCP_ACKNO(recved->packet, recved->parsed.transport_offset);
    unsigned seqno_them = TCP_SEQNO(recved->packet, recved->parsed.transport_offset);

    /*SYNACK*/
    if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
        TCP_FLAG_SYN|TCP_FLAG_ACK)) {
        item->is_success = 1;
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "syn-ack");

        uint16_t win_them =
            TCP_WIN(recved->packet, recved->parsed.transport_offset);
        if (win_them == 0) {
            safe_strcpy(item->classification, OUTPUT_CLS_LEN, "zerowin");
        } else {
            safe_strcpy(item->classification, OUTPUT_CLS_LEN, "open");

            /*stack(send) ack with probe*/

            unsigned char payload[PROBE_PAYLOAD_MAX_LEN];
            size_t payload_len = 0; 

            payload_len = ZBannerScan.probe->make_payload_cb(
                ip_them, port_them, ip_me, port_me,
                0, /*zbanner can recognize reponse by itself*/
                port_me-src_port_start,
                payload, PROBE_PAYLOAD_MAX_LEN);
            
            struct PacketBuffer *pkt_buffer = stack_get_packetbuffer(stack);

            pkt_buffer->length = tcp_create_packet(
                ip_them, port_them, ip_me, port_me,
                seqno_me, seqno_them+1, TCP_FLAG_ACK,
                payload, payload_len, pkt_buffer->px, PKT_BUF_LEN);
            
            stack_transmit_packetbuffer(stack, pkt_buffer);

            /*for multi-probe*/
            if (port_me==src_port_start && ZBannerScan.probe->probe_num) {
                for (unsigned idx=1; idx<ZBannerScan.probe->probe_num; idx++) {

                    unsigned cookie = get_cookie(ip_them, port_them, ip_me,
                        src_port_start+idx, entropy);

                    struct PacketBuffer *pkt_buffer = stack_get_packetbuffer(stack);

                    pkt_buffer->length = tcp_create_packet(
                        ip_them, port_them, ip_me, src_port_start+idx,
                        cookie, 0, TCP_FLAG_SYN,
                        NULL, 0, pkt_buffer->px, PKT_BUF_LEN);

                    stack_transmit_packetbuffer(stack, pkt_buffer);
            
                }
            }
        }
    }
    /*RST*/
    else if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
        TCP_FLAG_RST)) {
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "rst");
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "closed");
    }
    /*Banner*/
    else {
        item->is_success = 1;
        tcp_flags_to_string(
            TCP_FLAGS(recved->packet, recved->parsed.transport_offset),
            item->reason, OUTPUT_RSN_LEN);
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "serving");

        ZBannerScan.probe->handle_response_cb(
            ip_them, port_them, ip_me, port_me, port_me-src_port_start,
            &recved->packet[recved->parsed.app_offset],
            recved->parsed.app_length,
            item->report, OUTPUT_RPT_LEN);

        /*send rst to disconn*/
        struct PacketBuffer *pkt_buffer = stack_get_packetbuffer(stack);

        pkt_buffer->length = tcp_create_packet(
            ip_them, port_them, ip_me, port_me,
            seqno_me, seqno_them+1, TCP_FLAG_RST,
            NULL, 0, pkt_buffer->px, PKT_BUF_LEN);

        stack_transmit_packetbuffer(stack, pkt_buffer);
    }
}


struct ScanModule ZBannerScan = {
    .name = "zbanner",
    .required_probe_type = ProbeType_TCP,
    .desc =
        "ZBannerScan tries to contruct TCP conn with target port and send data "
        "from specified ProbeModule. Data in first reponse packet will be handled"
        " by specified ProbeModule.\n"
        "What important is the whole process was done in completely stateless. "
        "So ZBannerScan is very fast for large-scale probing like banner grabbing,"
        " service identification and etc.\n\n"
        "Must specify a ProbeModule for ZBannerScan like:\n"
        "    `--probe-module null`\n\n"
        "ZBannerScan will construct complete TCP conns. So must avoid Linux system "
        "sending RST automatically by adding iptable rule like:\n"
        "    `sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP -s <src-ip>`\n"
        "Line number of added rule could be checked like:\n"
        "    `sudo iptables -L --line-numbers`\n"
        "Remove the rule by its line number if we do not need it:\n"
        "    `sudo iptables -D OUTPUT <line-number>`\n",

    .global_init_cb               = &zbanner_global_init,
    .transmit_cb                  = &zbanner_transmit_packet,
    .validate_cb                  = &zbanner_validate,
    .handle_cb                    = &zbanner_handle,
    .close_cb                     = &scan_close_nothing,
};
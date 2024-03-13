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
udpprobe_transmit(
    uint64_t entropy,
    struct ScanTarget *target,
    struct ScanTimeoutEvent *event,
    unsigned char *px, size_t *len)
{
    /*we just handle udp target*/
    if (target->proto != Proto_UDP)
        return 0;
    
    unsigned cookie = get_cookie(target->ip_them, target->port_them,
        target->ip_me, src_port_start+target->index, entropy);

    struct ProbeTarget ptarget = {
        .ip_them   = target->ip_them,
        .ip_me     = target->ip_me,
        .port_them = target->port_them,
        .port_me   = src_port_start+target->index,
        .cookie    = cookie,
        .index     = target->index,
    };

    unsigned char payload[PROBE_PAYLOAD_MAX_LEN];
    size_t payload_len = 0;

    payload_len = UdpProbeScan.probe->make_payload_cb(&ptarget, payload);

    *len = udp_create_packet(target->ip_them, target->port_them,
        target->ip_me, src_port_start+target->index,
        payload, payload_len, px, PKT_BUF_LEN);
    
    /*add timeout*/
    event->need_timeout = 1;
    event->dedup_type   = 0;
    event->port_me      = src_port_start+target->index;
    
    /*for multi-probe*/
    if (UdpProbeScan.probe->multi_mode==Multi_Direct
        && target->index+1 < UdpProbeScan.probe->multi_num)
        return 1;
    else return 0;
    
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

        /**
         * UDP without data
         * It's conflict with `handle_reponse_cb` of ProbeModule
         * in semantic.
         * But ProbeModule is no need to handle responsed packets
         * without any data.
         * So I think its OK and Just record it*/
        if (!recved->parsed.app_length)
            return;

        struct ProbeTarget ptarget = {
            .ip_them   = recved->parsed.src_ip,
            .ip_me     = recved->parsed.dst_ip,
            .port_them = recved->parsed.port_src,
            .port_me   = recved->parsed.port_dst,
            .cookie    = get_cookie(recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, recved->parsed.port_dst, entropy),
            .index     = recved->parsed.port_dst-src_port_start,
        };

        if (UdpProbeScan.probe->validate_response_cb(&ptarget,
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
    struct stack_t *stack,
    struct FHandler *handler)
{
    if (recved->parsed.found == FOUND_UDP) {

        struct ProbeTarget ptarget = {
            .ip_them   = recved->parsed.src_ip,
            .ip_me     = recved->parsed.dst_ip,
            .port_them = recved->parsed.port_src,
            .port_me   = recved->parsed.port_dst,
            .cookie    = get_cookie(recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, recved->parsed.port_dst, entropy),
            .index     = recved->parsed.port_dst-src_port_start,
        };

        int is_multi = UdpProbeScan.probe->handle_response_cb(&ptarget,
            &recved->packet[recved->parsed.app_offset],
            recved->parsed.app_length, item);

        /*for multi-probe Multi_AfterHandle*/
        if (UdpProbeScan.probe->multi_mode==Multi_AfterHandle&&is_multi
            && recved->parsed.port_dst==src_port_start
            && UdpProbeScan.probe->multi_num) {

            for (unsigned idx=1; idx<UdpProbeScan.probe->multi_num; idx++) {

                struct PacketBuffer *pkt_buffer = stack_get_packetbuffer(stack);

                struct ProbeTarget ptarget = {
                    .ip_them   = recved->parsed.src_ip,
                    .ip_me     = recved->parsed.dst_ip,
                    .port_them = recved->parsed.port_src,
                    .port_me   = src_port_start+idx,
                    .cookie    = get_cookie(recved->parsed.src_ip, recved->parsed.port_src,
                        recved->parsed.dst_ip, src_port_start+idx, entropy),
                    .index     = idx,
                };

                unsigned char payload[PROBE_PAYLOAD_MAX_LEN];
                size_t payload_len = 0;

                payload_len = UdpProbeScan.probe->make_payload_cb(&ptarget, payload);

                pkt_buffer->length = udp_create_packet(
                    recved->parsed.src_ip, recved->parsed.port_src,
                    recved->parsed.dst_ip, src_port_start+idx,
                    payload, payload_len, pkt_buffer->px, PKT_BUF_LEN);

                stack_transmit_packetbuffer(stack, pkt_buffer);

                /*add timeout*/
                if (handler) {
                    struct ScanTimeoutEvent *tm_event =
                        CALLOC(1, sizeof(struct ScanTimeoutEvent));

                    tm_event->ip_them   = recved->parsed.src_ip;
                    tm_event->ip_me     = recved->parsed.dst_ip;
                    tm_event->port_them = recved->parsed.port_src;
                    tm_event->port_me   = src_port_start+idx;

                    tm_event->need_timeout = 1;
                    tm_event->dedup_type   = 0;

                    ft_add_event(handler, tm_event, global_now);
                    tm_event = NULL;
                }
        
            }

            return;
        }

        /*for multi-probe Multi_DynamicNext*/
        if (UdpProbeScan.probe->multi_mode==Multi_DynamicNext && is_multi) {

            struct PacketBuffer *pkt_buffer = stack_get_packetbuffer(stack);

            struct ProbeTarget ptarget = {
                .ip_them   = recved->parsed.src_ip,
                .ip_me     = recved->parsed.dst_ip,
                .port_them = recved->parsed.port_src,
                .port_me   = src_port_start+is_multi-1,
                .cookie    = get_cookie(recved->parsed.src_ip, recved->parsed.port_src,
                    recved->parsed.dst_ip, src_port_start+is_multi-1, entropy),
                .index     = is_multi-1,
            };

            unsigned char payload[PROBE_PAYLOAD_MAX_LEN];
            size_t payload_len = 0;

            payload_len = UdpProbeScan.probe->make_payload_cb(&ptarget, payload);

            pkt_buffer->length = udp_create_packet(
                recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, src_port_start+is_multi-1,
                payload, payload_len, pkt_buffer->px, PKT_BUF_LEN);

            stack_transmit_packetbuffer(stack, pkt_buffer);

            /*add timeout*/
            if (handler) {
                struct ScanTimeoutEvent *tm_event =
                    CALLOC(1, sizeof(struct ScanTimeoutEvent));

                tm_event->ip_them   = recved->parsed.src_ip;
                tm_event->ip_me     = recved->parsed.dst_ip;
                tm_event->port_them = recved->parsed.port_src;
                tm_event->port_me   = src_port_start+is_multi-1;

                tm_event->need_timeout = 1;
                tm_event->dedup_type   = 0;

                ft_add_event(handler, tm_event, global_now);
                tm_event = NULL;
            }

            return;
        }
    } else {
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "closed");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "port unreachable");
        unsigned proto;
        parse_icmp_port_unreachable(
            &recved->packet[recved->parsed.transport_offset],
            recved->parsed.transport_length,
            &item->ip_them, &item->port_them,
            &item->ip_me, &item->port_me, &proto);
        }
}

static void
udpprobe_timeout(
    uint64_t entropy,
    struct ScanTimeoutEvent *event,
    struct OutputItem *item,
    struct stack_t *stack,
    struct FHandler *handler)
{
    /*all events is for banner*/

    struct ProbeTarget ptarget = {
        .ip_them   = event->ip_them,
        .ip_me     = event->ip_me,
        .port_them = event->port_them,
        .port_me   = event->port_me,
        .cookie    = get_cookie(event->ip_them, event->port_them,
            event->ip_me, event->port_me, entropy),
        .index     = event->port_me-src_port_start,
    };

    int is_multi = UdpProbeScan.probe->handle_response_cb(&ptarget,
        NULL, 0, item);

    /*for multi-probe Multi_AfterHandle*/
    if (UdpProbeScan.probe->multi_mode==Multi_AfterHandle&&is_multi
        && event->port_me==src_port_start
        && UdpProbeScan.probe->multi_num) {

        for (unsigned idx=1; idx<UdpProbeScan.probe->multi_num; idx++) {

            struct PacketBuffer *pkt_buffer = stack_get_packetbuffer(stack);

            struct ProbeTarget ptarget = {
                .ip_them   = event->ip_them,
                .ip_me     = event->ip_me,
                .port_them = event->port_them,
                .port_me   = src_port_start+idx,
                .cookie    = get_cookie(event->ip_them, event->port_them,
                    event->ip_me, src_port_start+idx, entropy),
                .index     = idx,
            };

            unsigned char payload[PROBE_PAYLOAD_MAX_LEN];
            size_t payload_len = 0;

            payload_len = UdpProbeScan.probe->make_payload_cb(&ptarget, payload);

            pkt_buffer->length = udp_create_packet(
                event->ip_them, event->port_them,
                event->ip_me,   src_port_start+idx,
                payload, payload_len, pkt_buffer->px, PKT_BUF_LEN);

            stack_transmit_packetbuffer(stack, pkt_buffer);

            /*add timeout*/
            if (handler) {
                struct ScanTimeoutEvent *tm_event =
                    CALLOC(1, sizeof(struct ScanTimeoutEvent));

                tm_event->ip_them   = event->ip_them;
                tm_event->ip_me     = event->ip_me;
                tm_event->port_them = event->port_them;
                tm_event->port_me   = src_port_start+idx;

                tm_event->need_timeout = 1;
                tm_event->dedup_type   = 0;

                ft_add_event(handler, tm_event, global_now);
                tm_event = NULL;
            }
        }

        return;
    }

    /*for multi-probe Multi_DynamicNext*/
    if (UdpProbeScan.probe->multi_mode==Multi_DynamicNext && is_multi) {

        struct PacketBuffer *pkt_buffer = stack_get_packetbuffer(stack);

        struct ProbeTarget ptarget = {
            .ip_them   = event->ip_them,
            .ip_me     = event->ip_me,
            .port_them = event->port_them,
            .port_me   = src_port_start+is_multi-1,
            .cookie    = get_cookie(event->ip_them, event->port_them,
                event->ip_me, src_port_start+is_multi-1, entropy),
            .index     = is_multi-1,
        };

        unsigned char payload[PROBE_PAYLOAD_MAX_LEN];
        size_t payload_len = 0;

        payload_len = UdpProbeScan.probe->make_payload_cb(&ptarget, payload);

        pkt_buffer->length = udp_create_packet(
            event->ip_them, event->port_them,
            event->ip_me,   src_port_start+is_multi-1,
            payload, payload_len, pkt_buffer->px, PKT_BUF_LEN);

        stack_transmit_packetbuffer(stack, pkt_buffer);

        /*add timeout*/
        if (handler) {
            struct ScanTimeoutEvent *tm_event =
                CALLOC(1, sizeof(struct ScanTimeoutEvent));

            tm_event->ip_them   = event->ip_them;
            tm_event->ip_me     = event->ip_me;
            tm_event->port_them = event->port_them;
            tm_event->port_me   = src_port_start+is_multi-1;

            tm_event->need_timeout = 1;
            tm_event->dedup_type   = 0;

            ft_add_event(handler, tm_event, global_now);
            tm_event = NULL;
        }

        return;
    }

}

struct ScanModule UdpProbeScan = {
    .name                = "udpprobe",
    .required_probe_type = ProbeType_UDP,
    .support_timeout     = 1,
    .params              = NULL,
    .bpf_filter =
        "udp || (icmp && icmp[0]==3 && icmp[1]==3) || (icmp6 && icmp6[0]==1 && icmp6[1]==4)", /*udp and icmp port unreachable*/
    .desc =
        "UdpProbeScan sends a udp packet with ProbeModule data to target port "
        "and expects a udp response to believe the port is open or an icmp port "
        "unreachable message if closed. Responsed data will be processed and "
        "formed a report by ProbeModule.\n"
        "UdpProbeScan prefer the first reponse udp packet. But all packets to us "
        "could be record to pcap file.\n",

    .global_init_cb              = &udpprobe_global_init,
    .transmit_cb                 = &udpprobe_transmit,
    .validate_cb                 = &udpprobe_validate,
    .handle_cb                   = &udpprobe_handle,
    .timeout_cb                  = &udpprobe_timeout,
    .close_cb                    = &scan_close_nothing,
};
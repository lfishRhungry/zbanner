#include <stdlib.h>
#include <time.h>

#include "scan-modules.h"
#include "../xconf.h"
#include "../version.h"
#include "../massip/massip-cookie.h"
#include "../templ/templ-tcp.h"
#include "../stack/stack-tcp-core.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../util-scan/rstfilter.h"
#include "../util-out/logger.h"

extern struct ScanModule TcpStateScan; /*for internal x-ref*/

/**
 * For compatible with multi-recv-handlers and keeping internal thread-safe of
 * a TCP Conn table. We create multiple TCP Conn tables and one for each handler.
 * The key point is keeping same connection and its operation in its beloned TCP Conn table.
 * For this, we hash each connect to let it fixed on just one table.
 * 
 * !NOTE: Never CRUD a conn by a TCB if the conn does not belong to this table.
 * */
struct TCP_ConSet {
    struct TCP_ConnectionTable **tcpcons;
    unsigned count;
};

static struct TCP_ConSet tcpcon_set;

static uint64_t *tcb_count;
/**
 *For calc the conn index.
 * NOTE: We use a trick of src-port to differenciate multi-probes to avoid
 * mutual interference of connections.
 * Be careful to the source port range and probe num. Source port range is 256 in
 * default and can be set with flag `--source-port`.
*/
static unsigned src_port_start;

struct TcpStateConf {
    unsigned conn_expire;
    unsigned is_port_success:1;       /*--port-success*/
    unsigned record_ttl:1;
    unsigned record_ipid:1;
    unsigned record_win:1;
    unsigned record_mss:1;
};

static struct TcpStateConf tcpstate_conf = {0};

static enum ConfigRes SET_record_mss(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpstate_conf.record_mss = parseBoolean(value);

    return Conf_OK;
}

static enum ConfigRes SET_record_ttl(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpstate_conf.record_ttl = parseBoolean(value);

    return Conf_OK;
}

static enum ConfigRes SET_record_ipid(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpstate_conf.record_ipid = parseBoolean(value);

    return Conf_OK;
}

static enum ConfigRes SET_record_win(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpstate_conf.record_win = parseBoolean(value);

    return Conf_OK;
}

static enum ConfigRes SET_port_success(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpstate_conf.is_port_success = parseBoolean(value);

    return Conf_OK;
}

static enum ConfigRes SET_conn_expire(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);

    unsigned tm = parseInt(value);

    if (tm <= 0) {
        LOG(LEVEL_ERROR, "%s must be positive.\n", name);
        return Conf_ERR;
    }

    tcpstate_conf.conn_expire = tm;

    return Conf_OK;
}

static struct ConfigParam tcpstate_parameters[] = {
    {
        "conn-expire",
        SET_conn_expire,
        Type_NUM,
        {"expire", 0},
        "Specifies the max existing time of each connection."
    },
    {
        "port-success",
        SET_port_success,
        Type_BOOL,
        {"success-port", 0},
        "Let port opening(contains zero syn-ack) results as success level."
        "(Default is info level)"
    },
    {
        "record-ttl",
        SET_record_ttl,
        Type_BOOL,
        {"ttl", 0},
        "Records TTL for IPv4 or Hop Limit for IPv6 in SYN-ACK."
    },
    {
        "record-ipid",
        SET_record_ipid,
        Type_BOOL,
        {"ipid", 0},
        "Records IPID of SYN-ACK just for IPv4."
    },
    {
        "record-win",
        SET_record_win,
        Type_BOOL,
        {"win", "window", 0},
        "Records TCP window size of SYN-ACK."
    },
    {
        "record-mss",
        SET_record_mss,
        Type_BOOL,
        {"mss", 0},
        "Records TCP MSS option value of SYN-ACK if the option exists."
    },

    {0}
};

static bool tcpstate_init(const struct Xconf *xconf)
{
    if (tcpstate_conf.conn_expire <= 0)
        tcpstate_conf.conn_expire = 30;

    /*create rx_handler_count TCP tables for thread safe*/
    tcpcon_set.count   = xconf->rx_handler_count;
    tcpcon_set.tcpcons = 
        MALLOC(tcpcon_set.count * sizeof(struct TCP_ConnectionTable *));

    for (unsigned i=0; i<tcpcon_set.count; i++) {
        size_t entry_count = (size_t)(xconf->max_rate/5)/xconf->rx_handler_count;
        tcpcon_set.tcpcons[i] = tcpcon_create_table(
            entry_count>=10?entry_count:10, xconf->stack,
            &global_tmplset->pkts[Tmpl_Type_TCP],
            &global_tmplset->pkts[Tmpl_Type_TCP_SYN],
            &global_tmplset->pkts[Tmpl_Type_TCP_RST],
            (struct Output *)(&xconf->out),
            tcpstate_conf.conn_expire, xconf->seed);
    }

    tcb_count = &((struct Xconf *)xconf)->tcb_count;

    src_port_start = xconf->nic.src.port.first;

    return true;
}

static bool
tcpstate_transmit(
    uint64_t entropy,
    struct ScanTarget *target,
    struct ScanTmEvent *event,
    unsigned char *px, size_t *len)
{
    /*we just handle tcp target*/
    if (target->ip_proto != IP_PROTO_TCP)
        return false;

    unsigned cookie = get_cookie(target->ip_them, target->port_them,
        target->ip_me, src_port_start+target->index, entropy);

    *len = tcp_create_packet(
        target->ip_them, target->port_them, target->ip_me, src_port_start+target->index,
        cookie, 0, TCP_FLAG_SYN, NULL, 0, px, PKT_BUF_SIZE);

    /*multi-probe Multi_Direct*/
    if (TcpStateScan.probe->multi_mode==Multi_Direct
        && target->index+1<TcpStateScan.probe->multi_num)
        return true;

    return false;
}

static void
tcpstate_validate(
    uint64_t entropy,
    struct Received *recved,
    struct PreHandle *pre)
{
    if (recved->parsed.found == FOUND_TCP
        && recved->is_myip
        && recved->is_myport)
        pre->go_record = 1;
    else return;

    unsigned seqno_me  = TCP_ACKNO(recved->packet, recved->parsed.transport_offset);
    unsigned cookie    = get_cookie(recved->parsed.src_ip, recved->parsed.port_src,
            recved->parsed.dst_ip, recved->parsed.port_dst, entropy);

    /*just filter for syn-ack*/
    if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
        TCP_FLAG_SYN|TCP_FLAG_ACK)) {
        if (cookie != seqno_me - 1) {
            return;
        }
    }

    /*And we don't have to do dedup because TCP connection table will handle*/
    pre->go_dedup = 1;
    pre->no_dedup = 1;

    return;
}

static void
tcpstate_handle(
    unsigned th_idx,
    uint64_t entropy,
    struct Received *recved,
    struct OutputItem *item,
    struct stack_t *stack,
    struct FHandler *handler)
{
    /*in default*/
    item->no_output = 1;

    unsigned mss_them;
    bool     mss_found;
    uint16_t win_them;

    struct TCP_Control_Block   *tcb;
    struct TCP_ConnectionTable *tcpcon;

    ipaddress ip_them    = recved->parsed.src_ip;
    ipaddress ip_me      = recved->parsed.dst_ip;
    unsigned  port_them  = recved->parsed.port_src;
    unsigned  port_me    = recved->parsed.port_dst;
    unsigned  seqno_me   = TCP_ACKNO(recved->packet, recved->parsed.transport_offset);
    unsigned  seqno_them = TCP_SEQNO(recved->packet, recved->parsed.transport_offset);

    tcpcon = tcpcon_set.tcpcons[th_idx];
    tcb    = tcpcon_lookup_tcb(tcpcon, ip_me, ip_them, port_me, port_them);

    if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
        TCP_FLAG_SYN|TCP_FLAG_ACK)) {

        item->no_output = 0;

        /*zerowin could be a kind of port open*/
        if (tcpstate_conf.is_port_success) {
            item->level = OP_SUCCESS;
        }

        win_them = TCP_WIN(recved->packet, recved->parsed.transport_offset);

        if (tcpstate_conf.record_ttl)
            dach_printf(&item->report, "ttl", true, "%d", recved->parsed.ip_ttl);
        if (tcpstate_conf.record_ipid && recved->parsed.src_ip.version==4)
            dach_printf(&item->report, "ipid", true, "%d", recved->parsed.ip_v4_id);
        if (tcpstate_conf.record_win)
            dach_printf(&item->report, "win", true, "%d", win_them);
        if (tcpstate_conf.record_mss) {
            /*comput of mss is not easy*/
            mss_them = tcp_get_mss(recved->packet, recved->length, &mss_found);
            if (!mss_found) mss_them = 0;
            dach_printf(&item->report, "mss", true, "%d", mss_them);
        }

        /**
         * We have validated cookie for syn-ack in `tcpstate_validate`.
         * But also need to handle zero window
         * */

        if (win_them == 0) {
            safe_strcpy(item->classification, OP_CLS_SIZE, "fake-open");
            safe_strcpy(item->reason, OP_RSN_SIZE, "zerowin");
            return;
        } else {
            safe_strcpy(item->classification, OP_CLS_SIZE, "open");
            safe_strcpy(item->reason, OP_RSN_SIZE, "syn-ack");
        }

        if (tcb == NULL) {
            /*compute of mss is not easy*/
            mss_them = tcp_get_mss(recved->packet, recved->length, &mss_found);
            if (!mss_found) mss_them = 0;
            tcb = tcpcon_create_tcb(tcpcon, ip_me, ip_them, port_me, port_them,
                seqno_me, seqno_them+1, recved->parsed.ip_ttl, mss_them,
                TcpStateScan.probe, recved->secs, recved->usecs);
        }
        stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_SYNACK, 0, 0,
            recved->secs, recved->usecs, seqno_them+1, seqno_me);

        /*multi-probe Multi_IfOpen and filter zerowin*/
        if (TcpStateScan.probe->multi_mode==Multi_IfOpen
            && recved->parsed.port_dst==src_port_start) {

            for (unsigned idx=1; idx<TcpStateScan.probe->multi_num; idx++) {

                unsigned cookie = get_cookie(recved->parsed.src_ip, recved->parsed.port_src,
                    recved->parsed.dst_ip, src_port_start+idx, entropy);

                struct PacketBuffer *pkt_buffer = stack_get_packetbuffer(stack);

                pkt_buffer->length = tcp_create_packet(
                    recved->parsed.src_ip, recved->parsed.port_src,
                    recved->parsed.dst_ip, src_port_start+idx,
                    cookie, 0, TCP_FLAG_SYN,
                    NULL, 0, pkt_buffer->px, PKT_BUF_SIZE);

                stack_transmit_packetbuffer(stack, pkt_buffer);
            }
        }

    } else if (tcb) {
        /* If this has an ACK, then handle that first */
        if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
            TCP_FLAG_ACK)) {
            stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_ACK, 0, 0,
                recved->secs, recved->usecs, seqno_them, seqno_me);
        }

        /* If this contains payload, handle that second */
        if (recved->parsed.app_length) {
            stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_DATA,
                recved->packet+recved->parsed.app_offset,
                recved->parsed.app_length,
                recved->secs, recved->usecs,
                seqno_them, seqno_me);
        }

        /* If this is a FIN (also), handle that.
        Note that ACK + payload + FIN can come together */
        if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
            TCP_FLAG_FIN)
            &&
            !TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
            TCP_FLAG_RST)) {
            stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_FIN, 0, 0, 
                recved->secs, recved->usecs, 
                seqno_them + recved->parsed.app_length, /* the FIN comes after any data in the packet */
                seqno_me);
        }

        /* If this is a RST, then we'll be closing the connection */
        if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
            TCP_FLAG_RST)) {
            stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_RST, 0, 0,
                recved->secs, recved->usecs, seqno_them, seqno_me);
        }
    }
}

static void tcpstate_poll(unsigned th_idx)
{
    tcpcon_timeouts(tcpcon_set.tcpcons[th_idx], (unsigned)time(0), 0);
}

static void tcpstate_close()
{
    for (unsigned i=0; i<tcpcon_set.count; i++) {
        tcpcon_destroy_table(tcpcon_set.tcpcons[i]);
    }

    free(tcpcon_set.tcpcons);
    tcpcon_set.tcpcons = NULL;
}

static void tcpstate_status(char *status)
{
    uint64_t tcb_count = 0;

    if (tcpcon_set.tcpcons) {
        for (unsigned i=0; i<tcpcon_set.count; i++) {
            tcb_count += tcpcon_active_count(tcpcon_set.tcpcons[i]);
        }
    }

    snprintf(status, XTS_ADD_SIZE, "tcb=%"PRIu64, tcb_count);
}

struct ScanModule TcpStateScan = {
    .name                = "tcp-state",
    .required_probe_type = ProbeType_STATE,
    .support_timeout     = 0,
    .bpf_filter          = "tcp",
    .params              = tcpstate_parameters,
    .desc =
        "TcpStateScan tries to contruct TCP conn with target port with a hybrid-state"
        " lightweight TCP stack(HLTCP) and do further scan. It could do more things "
        "than ZBannerScan like grabbing complete webpage, further interacting with"
        " server and etc. But TcpStateScan consumes more resources because of the "
        "complex user-space TCP stack and stateful connections.\n"
        "NOTE1: TcpStateScan use its own timeout machanism in the TCP stack, so "
        "`--timeout` is useless.\n"
        "NOTE2: Must specify a StateType ProbeModule for TcpStateScan like:\n"
        "    `--probe-module xxx`\n"
        "NOTE3: TcpStateScan will construct complete TCP conns. So must avoid Linux"
        " system sending RST automatically by adding iptable rules displayed in "
        "`firewall` directory.\n"
        "NOTE4: TcpStateScan causes so many packets with little data because of the "
        "default small -tcp-win. You may set a new -tcp-win and adjust -max-pkt-len"
        " to achieve a fast communicating. Yeah, I don't know why the MSS could be"
        " useless than -tcp-win.\n"
        "NOTE5: TcpStateScan uses an incomplete TCP protocol which has just 3 states"
        " and acknowledges data pkt by pkt. This is because we want our TCP stack"
        " to be light-weight and fast in specific scenarios. Specific scenarios"
        " means little data exchanging in less times and our original purpose of "
        "TcpStateScan is to get banners over TLS with TlsStateProbe.\n"
        "NOTE6: Remember that "XTATE_FIRST_UPPER_NAME" is not a browser, crawler"
        " or any other tools concentrated on contents in protocol. We must focus"
        " on protocol itself with activate scanning.\n"
        "NOTE7: Slow send rate may cause target host's retransmition.",

    .init_cb                = &tcpstate_init,
    .transmit_cb            = &tcpstate_transmit,
    .validate_cb            = &tcpstate_validate,
    .handle_cb              = &tcpstate_handle,
    .timeout_cb             = &scan_no_timeout,
    .poll_cb                = &tcpstate_poll,
    .close_cb               = &tcpstate_close,
    .status_cb              = &tcpstate_status,
};
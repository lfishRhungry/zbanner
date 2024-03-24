#include <stdlib.h>
#include <time.h>

#include "scan-modules.h"
#include "../cookie.h"
#include "../xconf.h"
#include "../templ/templ-tcp.h"
#include "../stack/stack-tcp-core.h"
#include "../util/safe-string.h"
#include "../util/fine-malloc.h"
#include "../util/rstfilter.h"
#include "../util/logger.h"

extern struct ScanModule TcpStateScan; /*for internal x-ref*/

static struct TCP_ConnectionTable *tcpcon = NULL;

static uint64_t *tcb_count;

struct TcpStateConf {
    unsigned conn_timeout;
};

static struct TcpStateConf tcpstate_conf = {0};

static int SET_conn_timeout(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);

    unsigned tm = parseInt(value);

    if (tm <= 0) {
        fprintf(stderr, "FAIL: %s must be positive.\n", name);
        return CONF_ERR;
    }

    tcpstate_conf.conn_timeout = tm;

    return CONF_OK;
}

static struct ConfigParameter tcpstate_parameters[] = {
    {
        "conn-timeout",
        SET_conn_timeout,
        F_NUMABLE,
        {"conn-timeout", "timeout", "conn-tm", "tm", 0},
        "Specifies the max existing time of each connection."
    },

    {0}
};

static int tcpstate_global_init(const struct Xconf *xconf)
{
    if (tcpstate_conf.conn_timeout <= 0)
        tcpstate_conf.conn_timeout = 30;

    tcpcon = tcpcon_create_table(
        (size_t)(xconf->max_rate/5)/xconf->tx_thread_count,
        xconf->stack, &global_tmplset->pkts[Proto_TCP],
        (struct Output *)(&xconf->output),
        tcpstate_conf.conn_timeout, xconf->seed);
    
    tcb_count = &((struct Xconf *)xconf)->tcb_count;

    return 1;
}

static int
tcpstate_transmit_packet(
    uint64_t entropy,
    struct ScanTarget *target,
    struct ScanTimeoutEvent *event,
    unsigned char *px, size_t *len)
{
    /*we just handle tcp target*/
    if (target->proto != Proto_TCP)
        return 0;

    unsigned cookie = get_cookie(target->ip_them, target->port_them,
        target->ip_me, target->port_me, entropy);

    *len = tcp_create_packet(
        target->ip_them, target->port_them, target->ip_me, target->port_me,
        cookie, 0, TCP_FLAG_SYN, NULL, 0, px, PKT_BUF_LEN);

    return 0;
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
    uint64_t entropy,
    struct Received *recved,
    struct OutputItem *item,
    struct stack_t *stack,
    struct FHandler *handler)
{
    /*it's not elegent now*/
    item->no_output = 1;

    ipaddress ip_them    = recved->parsed.src_ip;
    ipaddress ip_me      = recved->parsed.dst_ip;
    unsigned  port_them  = recved->parsed.port_src;
    unsigned  port_me    = recved->parsed.port_dst;
    unsigned  seqno_me   = TCP_ACKNO(recved->packet, recved->parsed.transport_offset);
    unsigned  seqno_them = TCP_SEQNO(recved->packet, recved->parsed.transport_offset);

    struct TCP_Control_Block *tcb;

    /* does a TCB already exist for this connection? */
    tcb = tcpcon_lookup_tcb(tcpcon, ip_me, ip_them, port_me, port_them);

    if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
        TCP_FLAG_SYN|TCP_FLAG_ACK)) {
        /*we have validated cookie for syn-ack in `tcpstate_validate`*/
        if (tcb == NULL) {
            tcb = tcpcon_create_tcb(tcpcon, ip_me, ip_them, port_me, port_them,
                seqno_me, seqno_them+1, recved->parsed.ip_ttl,
                TcpStateScan.probe, recved->secs, recved->usecs);
        }
        stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_SYNACK, 0, 0,
            recved->secs, recved->usecs, seqno_them+1, seqno_me);

    } else if (tcb) {
        /* If this is an ACK, then handle that first */
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

void tcpstate_poll()
{
    /*update timeout events*/
    tcpcon_timeouts(tcpcon, (unsigned)time(0), 0);
    /*update tcb count*/
    (*tcb_count) = tcpcon_active_tcb(tcpcon);
}

void tcpstate_close()
{
    tcpcon_destroy_table(tcpcon);
}

struct ScanModule TcpStateScan = {
    .name                = "tcp-state",
    .required_probe_type = ProbeType_STATE,
    .support_timeout     = 0,
    .bpf_filter          = "tcp",
    .params              = tcpstate_parameters,
    .desc =
        "TcpStateScan tries to contruct TCP conn with target port with a user-space"
        " TCP stack and do communication. Used ProbeModule could do more things "
        "than ZBannerScan like grabbing complete webpage, further interacting with"
        " server and etc. But TcpStateScan consumes more resources because of the "
        "complex user-space TCP stack and stateful connections.\n"
        "TcpStateScan use its own timeout machanism in the TCP stack, so `--timeout`"
        " is useless.\n"
        "Must specify a StateType ProbeModule for TcpStateScan like:\n"
        "    `--probe-module xxx`\n"
        "TcpStateScan will construct complete TCP conns. So must avoid Linux system "
        "sending RST automatically by adding iptable rule like:\n"
        "    `sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP -s <src-ip>`\n"
        "Line number of added rule could be checked like:\n"
        "    `sudo iptables -L --line-numbers`\n"
        "Remove the rule by its line number if we do not need it:\n"
        "    `sudo iptables -D OUTPUT <line-number>`",

    .global_init_cb               = &tcpstate_global_init,
    .transmit_cb                  = &tcpstate_transmit_packet,
    .validate_cb                  = &tcpstate_validate,
    .handle_cb                    = &tcpstate_handle,
    .timeout_cb                   = &scan_no_timeout,
    .poll_cb                      = &tcpstate_poll,
    .close_cb                     = &tcpstate_close,
};
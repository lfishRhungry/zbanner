#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "globals.h"
#include "receive.h"
#include "transmit.h"
#include "version.h"
#include "xconf.h"

#include "stub/stub-pcap.h"
#include "templ/templ-init.h"
#include "nmap/nmap-service.h"

#include "target/target-cookie.h"
#include "target/target-parse.h"

#include "rawsock/rawsock.h"

#include "pixie/pixie-backtrace.h"
#include "pixie/pixie-threads.h"
#include "pixie/pixie-timer.h"

#include "util-out/logger.h"
#include "util-out/xtatus.h"
#include "util-scan/init-nic.h"
#include "util-scan/list-targets.h"
#include "util-data/fine-malloc.h"

#include "output-modules/bson-output.h"
#include "output-modules/mongodb-output.h"

#if defined(WIN32)
#include <WinSock.h>
#if defined(_MSC_VER)
#pragma comment(lib, "Ws2_32.lib")
#endif
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

/*
 * Use to hint Tx & Rx threads.
 * Should not be modified by Tx or Rx thread themselves but by
 * `mainscan` or `control_c_handler`
 */
unsigned volatile time_to_finish_tx = 0;
unsigned volatile time_to_finish_rx = 0;

/*
 * We update a global time in xtatus.c for less syscall.
 * Use this if you need rough and not accurate current time.
 */
time_t   global_now;
/**
 * This is for some wrappered functions that use TemplateSet to create packets.
 * !Do not modify it unless u know what u are doing.
 */
TmplSet *global_tmplset;

static uint64_t usec_start;

static void _control_c_handler(int x) {
    static unsigned control_c_pressed = 0;

    if (control_c_pressed == 0) {
        LOG(LEVEL_OUT, "waiting several seconds to exit..."
                       "                                                       "
                       "                    \n");
        /*First time of <ctrl-c>, tell Tx to stop*/
        control_c_pressed = 1;
        time_to_finish_tx = 1;
    } else {
        if (time_to_finish_rx) {
            /*Not first time of <ctrl-c> */
            /*and Rx is exiting, we just warn*/
            LOG(LEVEL_OUT, "\nERROR: Rx Thread is still running\n");
            /*Exit many <ctrl-c>*/
            if (time_to_finish_rx++ > 1)
                exit(1);
        } else {
            /*Not first time of <ctrl-c> */
            /*and we are waiting now*/
            /*tell Rx to exit*/
            time_to_finish_rx = 1;
        }
    }
}

static int _main_scan(XConf *xconf) {
    /**
     * According to C99 standards while using designated initializer:
     *
     *     "Omitted fields are implicitly initialized the same as for objects
     * that have static storage duration."
     *
     * ref: https://gcc.gnu.org/onlinedocs/gcc/Designated-Inits.html
     *
     * This is more efficient to got an all-zero var than memset and could got
     * a partial-zero var conveniently.
     */
    bool       stop_tx         = true;
    uint64_t   count_targets   = 0;
    uint64_t   count_endpoints = 0;
    uint64_t   scan_range      = 0;
    bool       init_ipv4       = false;
    bool       init_ipv6       = false;
    time_t     now             = time(0);
    TmplSet    tmplset         = {0};
    Xtatus     status          = {.last = {0}};
    XtatusItem status_item     = {0};
    RxThread   rx_thread[1]    = {{0}};
    TxThread  *tx_thread;
    double     tx_free_entries;
    double     rx_free_entries;
    double     rx_queue_ratio_tmp;

    tx_thread = CALLOC(xconf->tx_thread_count, sizeof(TxThread));

    /*
     * Set modules at first for dependency checking in module initing.
     * Output & Probe don't need explicit default setting.
     */
    if (!xconf->generator) {
        xconf->generator = get_generate_module_by_name("blackrock");
        LOG(LEVEL_DEBUG, "Default GenerateModule `blackrock` is chosen because "
                         "no GenerateModule "
                         "was specified.\n");
    }
    if (!xconf->scanner) {
        xconf->scanner = get_scan_module_by_name("tcp-syn");
        LOG(LEVEL_DEBUG,
            "Default ScanModule `tcpsyn` is chosen because no ScanModule "
            "was specified.\n");
    }

    /*validate probe type*/
    if (xconf->scanner->required_probe_type == ProbeType_NULL) {
        if (xconf->probe) {
            LOG(LEVEL_ERROR, "ScanModule %s does not support any probe.\n",
                xconf->scanner->name);
            exit(1);
        }
    } else {
        if (!xconf->probe ||
            xconf->probe->type != xconf->scanner->required_probe_type) {
            LOG(LEVEL_ERROR, "ScanModule %s needs probe of %s type.\n",
                xconf->scanner->name,
                get_probe_type_name(xconf->scanner->required_probe_type));
            exit(1);
        }
    }

    /*
     * Config params & Do global init for GenerateModule
     */
    if (xconf->generator_args && xconf->generator->params) {
        if (set_parameters_from_substring(NULL, xconf->generator->params,
                                          xconf->generator_args)) {
            LOG(LEVEL_ERROR, "sub param parsing of GenerateModule.\n");
            exit(1);
        }
    }
    if (!xconf->generator->init_cb(xconf, &count_targets, &count_endpoints,
                                   &init_ipv4, &init_ipv6)) {
        LOG(LEVEL_ERROR, "global init of GenerateModule.\n");
        exit(1);
    }

    LOG(LEVEL_DETAIL, "init_ipv4 from generator: %s\n",
        init_ipv4 ? "true" : "false");
    LOG(LEVEL_DETAIL, "init_ipv6 from generator: %s\n",
        init_ipv6 ? "true" : "false");

    init_ipv4 = xconf->set_ipv4_adapter ? xconf->init_ipv4_adapter : init_ipv4;
    init_ipv6 = xconf->set_ipv6_adapter ? xconf->init_ipv6_adapter : init_ipv6;
    if (!init_ipv4 && !init_ipv6) {
        LOG(LEVEL_ERROR, "neither ipv4 & ipv6 adapter would be inited.\n");
        LOG(LEVEL_HINT, "we can manually init adapter like `-init-ipv4`.\n");
        exit(1);
    }

    scan_range = count_targets * count_endpoints;

    LOG(LEVEL_DETAIL, "count_targets from generator: %" PRIu64 "\n",
        count_targets);
    LOG(LEVEL_DETAIL, "count_endpoints from generator: %" PRIu64 "\n",
        count_targets);
    LOG(LEVEL_DETAIL, "scan_range from generator: %" PRIu64 "\n", scan_range);

    /**
     * Optimize target again because generator may add new targets.
     */
    targetset_optimize(&xconf->targets);

    /*before rawsock initing*/
    rawsock_prepare();

    /*init NIC & rawsock*/
    if (init_nic(xconf, init_ipv4, init_ipv6) != 0)
        exit(1);
    if (!xconf->nic.is_usable) {
        LOG(LEVEL_ERROR, "failed to detect IP of interface\n");
        LOG(LEVEL_HINT, "did you spell the interface name correctly?\n");
        LOG(LEVEL_HINT, "if it has no IP address, "
                        "manually set with \"--adapter-ip 192.168.100.5\"\n");
        exit(1);
    }

    /*
     * Set the "source ports" of everything we transmit.
     */
    if (xconf->nic.src.port.range == 0) {
        unsigned port             = 40000 + now % 20000;
        xconf->nic.src.port.first = port;
        xconf->nic.src.port.last  = port + XCONF_DFT_PORT_RANGE;
        xconf->nic.src.port.range =
            xconf->nic.src.port.last - xconf->nic.src.port.first;
    }

    /*
     * create callback queue
     */
    xconf->stack = stack_create(xconf->nic.source_mac, &xconf->nic.src,
                                xconf->stack_buf_count);

    /*
     * Initialize the packet templates and attributes
     */
    xconf->tmplset = &tmplset;
    global_tmplset = &tmplset;

    /* it should be set before template init*/
    if (xconf->tcp_init_window)
        template_set_tcp_syn_window_of_default(xconf->tcp_init_window);

    if (xconf->tcp_window)
        template_set_tcp_window_of_default(xconf->tcp_window);

    template_packet_init(xconf->tmplset, xconf->nic.source_mac,
                         xconf->nic.router_mac_ipv4, xconf->nic.router_mac_ipv6,
                         rawsock_if_datalink(xconf->nic.adapter), xconf->seed,
                         xconf->templ_opts);

    if (xconf->packet_ttl)
        template_set_ttl(xconf->tmplset, xconf->packet_ttl);

    if (xconf->nic.is_vlan)
        template_set_vlan(xconf->tmplset, xconf->nic.vlan_id);

    /*
     * Config params & Do global init for ScanModule
     */
    xconf->scanner->probe = xconf->probe;

    if (xconf->scanner_args && xconf->scanner->params) {
        if (set_parameters_from_substring(NULL, xconf->scanner->params,
                                          xconf->scanner_args)) {
            LOG(LEVEL_ERROR, "sub param parsing of ScanModule.\n");
            exit(1);
        }
    }
    if (!xconf->scanner->init_cb(xconf)) {
        LOG(LEVEL_ERROR, "global init of ScanModule.\n");
        exit(1);
    }

    /*
     * Config params & Do global init for ProbeModule
     */
    if (xconf->probe) {
        if (xconf->probe_args && xconf->probe->params) {
            if (set_parameters_from_substring(NULL, xconf->probe->params,
                                              xconf->probe_args)) {
                LOG(LEVEL_ERROR, "sub param parsing of ProbeModule.\n");
                exit(1);
            }
        }

        if (!xconf->probe->init_cb(xconf)) {
            LOG(LEVEL_ERROR, "ProbeModule global initializing\n");
            exit(1);
        }
    }

    /*
     * Do init for OutputModule
     */
    if (!output_init(xconf, &xconf->out_conf)) {
        LOG(LEVEL_ERROR, "OutputModule initializing\n");
        exit(1);
    }

    /*
     * BPF filter
     * We set BPF filter for pcap at last to avoid the filter affect router-mac
     * getting by ARP.
     * And the filter string is combined from ProbeModule and user setting.
     */
    if (!xconf->is_no_bpf) {
        rawsock_set_filter(xconf->nic.adapter, xconf->scanner->bpf_filter,
                           xconf->bpf_filter);
    }

    /*
     * trap <ctrl-c>
     */
    signal(SIGINT, _control_c_handler);

    /*
     * Prepare for tx threads
     */
    for (unsigned index = 0; index < xconf->tx_thread_count; index++) {
        TxThread *parms           = &tx_thread[index];
        parms->xconf              = xconf;
        parms->tx_index           = index;
        parms->my_index           = xconf->resume.index;
        parms->done_transmitting  = false;
        parms->thread_handle_xmit = 0;
    }
    /*
     * Prepare for rx thread
     */
    rx_thread->xconf              = xconf;
    rx_thread->done_receiving     = false;
    rx_thread->thread_handle_recv = 0;
    /** needed for --packet-trace option so that we know when we started
     * the scan
     */
    rx_thread->pt_start           = 1.0 * pixie_gettime() / 1000000.0;

    /*
     * Print helpful text
     */
    char      buffer[80];
    struct tm x;

    now = time(0);
    safe_gmtime(&x, &now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S GMT", &x);
    LOG(LEVEL_OUT,
        "\nStarting " XTATE_NAME_TITLE_CASE " " XTATE_VERSION " at %s\n",
        buffer);
    LOG(LEVEL_OUT, "(" XTATE_GITHUB_URL ")\n");

    LOG(LEVEL_OUT, "Scanner:    %s\n", xconf->scanner->name);
    if (xconf->probe)
        LOG(LEVEL_OUT, "Probe:      %s\n", xconf->probe->name);
    LOG(LEVEL_OUT, "Generator:  %s\n", xconf->generator->name);
    if (xconf->out_conf.output_module)
        LOG(LEVEL_OUT, "Output:     %s\n", xconf->out_conf.output_module->name);

    LOG(LEVEL_OUT, "Interface:  %s\n", xconf->nic.ifname);
    LOG(LEVEL_OUT, "IP version:");
    if (init_ipv4)
        LOG(LEVEL_OUT, " v4");
    if (init_ipv6)
        LOG(LEVEL_OUT, " v6");
    LOG(LEVEL_OUT, "\n");
    /**
     * We use target and endpoint for generalizing.
     * Not all modules would using host and port. A target can be an IP, URL or
     * any others. An endpoint can be a port, TTL, IP protocol, sub-directory or
     * any others.
     */
    if (count_targets > 0) {
        LOG(LEVEL_OUT, "Scanning %" PRIu64 " targets", count_targets);
        if (count_endpoints > 1) {
            LOG(LEVEL_OUT, " [%" PRIu64 " endpoints each]", count_endpoints);
        }
        LOG(LEVEL_OUT, "\n");
    } else {
        LOG(LEVEL_OUT, "Scanning a dynamic number of targets\n");
    }
    LOG(LEVEL_OUT, "\n");

    /*
     * Start tx & rx threads
     */
    rx_thread->thread_handle_recv =
        pixie_begin_thread(receive_thread, 0, rx_thread);
    for (unsigned index = 0; index < xconf->tx_thread_count; index++) {
        TxThread *parms = &tx_thread[index];
        parms->thread_handle_xmit =
            pixie_begin_thread(transmit_thread, 0, parms);
    }

    /**
     * set status outputing
     */
    xtatus_start(&status);
    status.print_queue    = xconf->is_status_queue;
    status.print_info_num = xconf->is_status_info_num;
    status.print_hit_rate = xconf->is_status_hit_rate;
    status.is_infinite    = xconf->is_infinite;
    status.no_ansi        = xconf->is_no_ansi;

    /*
     * Now wait for <ctrl-c> to be pressed OR for Tx Threads to exit.
     * Tx Threads can shutdown by themselves for finishing their tasks.
     * We also can use <ctrl-c> to make them exit early.
     * All controls are decided by global variable `time_to_finish_tx`.
     */
    pixie_usleep(1000 * 100);
    LOG(LEVEL_INFO, "waiting for threads to finish\n");
    while (!time_to_finish_tx) {
        /* Find the min-index, repeat and rate */
        status_item.total_sent   = 0;
        status_item.cur_pps      = 0.0;
        status_item.cur_count    = UINT64_MAX;
        status_item.repeat_count = UINT64_MAX;
        stop_tx                  = true;
        for (unsigned i = 0; i < xconf->tx_thread_count; i++) {
            TxThread *parms = &tx_thread[i];

            if (status_item.cur_count > parms->my_index)
                status_item.cur_count = parms->my_index;

            if (status_item.repeat_count > parms->my_repeat)
                status_item.repeat_count = parms->my_repeat;

            status_item.cur_pps += parms->throttler->current_rate;
            status_item.total_sent += parms->total_sent;

            stop_tx &= (!xconf->generator->hasmore_cb(i, parms->my_index));
        }

        /**
         * Rx handle queue is the bottle-neck, we got the most severe one.
         */
        status_item.rx_queue_ratio = 100.0;
        if (rx_thread->handle_q) {
            for (unsigned i = 0; i < xconf->rx_handler_count; i++) {
                rx_free_entries = rte_ring_free_count(rx_thread->handle_q[i]);
                rx_queue_ratio_tmp = rx_free_entries * 100.0 /
                                     (double)(xconf->dispatch_buf_count);

                if (status_item.rx_queue_ratio > rx_queue_ratio_tmp)
                    status_item.rx_queue_ratio = rx_queue_ratio_tmp;
            }
        }

        /**
         * Tx handle queue maybe short if something wrong.
         */
        tx_free_entries = rte_ring_free_count(xconf->stack->transmit_queue);
        status_item.tx_queue_ratio =
            tx_free_entries * 100.0 / (double)xconf->stack_buf_count;

        /* Note: This is how we tell the Tx has ended */
        if (xconf->is_infinite) {
            if (xconf->repeat && status_item.repeat_count >= xconf->repeat)
                time_to_finish_tx = 1;
        } else {
            if (stop_tx)
                time_to_finish_tx = 1;
        }

        /**
         * additional status from scan module
         */
        status_item.add_status[0] = '\0';
        xconf->scanner->status_cb(status_item.add_status);

        /**
         * update other status item fields
         */
        status_item.total_successed = xconf->out_conf.total_successed;
        status_item.total_failed    = xconf->out_conf.total_failed;
        status_item.total_info      = xconf->out_conf.total_info;
        status_item.max_count       = scan_range;
        status_item.print_in_json   = xconf->is_status_ndjson;

        if (!xconf->is_no_status)
            xtatus_print(&status, &status_item);

        /* Sleep for almost a second */
        pixie_mssleep(500);
    }

    /*
     * If we haven't completed the scan, then save the resume
     * information.
     */
    if (status_item.cur_count < scan_range && !xconf->is_infinite &&
        !xconf->is_noresume) {
        xconf->resume.index = status_item.cur_count;
        xconf_save_state(xconf);
    }

    /*
     * Now Tx Threads have breaked out the main loop of sending because of
     * `time_to_finish_tx` and go into loop of `stack_flush_packets` before
     * `time_to_finish_rx`. Rx Thread exits just by our setting of
     * `time_to_finish_rx` according to time waiting. So `time_to_finish_rx` is
     * the important signal both for Tx/Rx Thread to exit.
     */
    now = time(0);
    for (;;) {
        /* Find the min-index, repeat and rate */
        status_item.total_sent   = 0;
        status_item.cur_pps      = 0.0;
        status_item.cur_count    = UINT64_MAX;
        status_item.repeat_count = UINT64_MAX;
        for (unsigned i = 0; i < xconf->tx_thread_count; i++) {
            TxThread *parms = &tx_thread[i];

            if (status_item.cur_count > parms->my_index)
                status_item.cur_count = parms->my_index;

            if (status_item.repeat_count > parms->my_repeat)
                status_item.repeat_count = parms->my_repeat;

            status_item.cur_pps += parms->throttler->current_rate;
            status_item.total_sent += parms->total_sent;
        }

        /**
         * Rx handle queue is the bottle-neck, we got the most severe one.
         */
        status_item.rx_queue_ratio = 100.0;
        if (rx_thread->handle_q) {
            for (unsigned i = 0; i < xconf->rx_handler_count; i++) {
                rx_free_entries = rte_ring_free_count(rx_thread->handle_q[i]);
                rx_queue_ratio_tmp = rx_free_entries * 100.0 /
                                     (double)(xconf->dispatch_buf_count);

                if (status_item.rx_queue_ratio > rx_queue_ratio_tmp)
                    status_item.rx_queue_ratio = rx_queue_ratio_tmp;
            }
        }

        /**
         * Tx handle queue maybe short if something wrong.
         */
        tx_free_entries = rte_ring_free_count(xconf->stack->transmit_queue);
        status_item.tx_queue_ratio =
            tx_free_entries * 100.0 / (double)xconf->stack_buf_count;

        /**
         * additional status from scan module
         */
        status_item.add_status[0] = '\0';
        xconf->scanner->status_cb(status_item.add_status);

        /**
         * update other status item fields
         */
        status_item.total_successed = xconf->out_conf.total_successed;
        status_item.total_failed    = xconf->out_conf.total_failed;
        status_item.total_info      = xconf->out_conf.total_info;
        status_item.max_count       = scan_range;
        status_item.print_in_json   = xconf->is_status_ndjson;
        status_item.exiting_secs    = xconf->wait - (time(0) - now);

        if (!xconf->is_no_status)
            xtatus_print(&status, &status_item);

        /*no more waiting or too many <ctrl-c>*/
        if (time(0) - now >= xconf->wait || time_to_finish_rx) {
            LOG(LEVEL_DEBUG, "telling threads to exit...\n");
            time_to_finish_rx = 1;
            break;
        }

        pixie_mssleep(350);
    }

    for (unsigned i = 0; i < xconf->tx_thread_count; i++) {
        TxThread *parms = &tx_thread[i];
        pixie_thread_join(parms->thread_handle_xmit);
    }
    pixie_thread_join(rx_thread->thread_handle_recv);

    uint64_t usec_now = pixie_gettime();
    LOG(LEVEL_OUT,
        "\n%u milliseconds elapsed: [+]=%" PRIu64 " [x]=%" PRIu64
        " [*]=%" PRIu64 "\n",
        (unsigned)((usec_now - usec_start) / 1000), status_item.total_successed,
        status_item.total_failed, status_item.total_info);

    /*
     * Now cleanup everything
     */
    xtatus_finish(&status);

    xconf->scanner->close_cb();

    if (xconf->probe) {
        xconf->probe->close_cb();
    }

    xconf->generator->close_cb();

    output_close(&xconf->out_conf);

    FREE(tx_thread);

    rawsock_close_adapter(xconf->nic.adapter);

    LOG(LEVEL_INFO, "all threads exited...\n");

    return 0;
}

/***************************************************************************
 ***************************************************************************/
int main(int argc, char *argv[]) {
    /*init logger at first*/
    LOG_init();

    XConf xconf[1];
    memset(xconf, 0, sizeof(xconf));

#if defined(WIN32)
    {
        WSADATA x;
        WSAStartup(0x101, &x);
    }
#endif

    usec_start = pixie_gettime();
    global_now = time(0);

    /* Set system to report debug information on crash */
    int is_backtrace = 1;
    for (unsigned i = 1; i < (unsigned)argc; i++) {
        if (argv[i][0] == '-' && (EQUALS(argv[i] + 1, "nobacktrace") ||
                                  EQUALS(argv[i] + 1, "nobt"))) {
            is_backtrace = 0;
        }
    }
    if (is_backtrace) {
        pixie_backtrace_init(argv[0]);
    } else {
        LOG(LEVEL_WARN, "backtrace to program call stack is off.\n");
    }

    //=================================================Define default params
    xconf->tx_thread_count    = XCONF_DFT_TX_THD_COUNT;
    xconf->rx_handler_count   = XCONF_DFT_RX_HDL_COUNT;
    xconf->stack_buf_count    = XCONF_DFT_STACK_BUF_COUNT;
    xconf->dispatch_buf_count = XCONF_DFT_DISPATCH_BUF_COUNT;
    xconf->max_rate           = XCONF_DFT_MAX_RATE;
    xconf->dedup_win          = XCONF_DFT_DEDUP_WIN;
    xconf->shard.one          = XCONF_DFT_SHARD_ONE;
    xconf->shard.of           = XCONF_DFT_SHARD_OF;
    xconf->wait               = XCONF_DFT_WAIT;
    xconf->nic.snaplen        = XCONF_DFT_SNAPLEN;
    xconf->max_packet_len     = XCONF_DFT_MAX_PKT_LEN;
    xconf->packet_ttl         = XCONF_DFT_PACKET_TTL;
    xconf->tcp_init_window    = XCONF_DFT_TCP_SYN_WINSIZE;
    xconf->tcp_window         = XCONF_DFT_TCP_OTHER_WINSIZE;
    xconf->sendmmsg_batch     = XCONF_DFT_SENDMMSG_BATCH;
    xconf->sendmmsg_retries   = XCONF_DFT_SENDMMSG_RETRIES;
    xconf->sendq_size         = XCONF_DFT_SENDQUEUE_SIZE;
    //=================================================

    //=================================================read conf from args
    xconf_command_line(xconf, argc, argv);

    /* logger should be prepared early */
    LOG_set_ansi(xconf->is_no_ansi);

    /* entropy for randomness */
    if (xconf->seed == 0)
        xconf->seed = get_one_entropy();

    /* init AS info for global and output module*/
    xconf->as_query =
        as_query_new(xconf->ip2asn_v4_filename, xconf->ip2asn_v6_filename);
    xconf->out_conf.as_query = xconf->as_query;

    /**
     * Add target by ASN
     */
    if (xconf->target_asn_v4) {
        if (xconf->as_query == NULL) {
            LOG(LEVEL_ERROR,
                "cannot add ipv4 target by ASN because no AS info loaded.\n");
            exit(1);
        }
        int err = targetset_add_asn_v4_string(&xconf->targets, xconf->as_query,
                                              xconf->target_asn_v4);
        if (err) {
            LOG(LEVEL_ERROR, "add ipv4 target failed by ASN string.\n");
            exit(1);
        }
    }
    if (xconf->target_asn_v6) {
        if (xconf->as_query == NULL) {
            LOG(LEVEL_ERROR,
                "cannot add ipv6 target by ASN because no AS info loaded.\n");
            exit(1);
        }
        int err = targetset_add_asn_v6_string(&xconf->targets, xconf->as_query,
                                              xconf->target_asn_v6);
        if (err) {
            LOG(LEVEL_ERROR, "add ipv6 target failed by ASN string.\n");
            exit(1);
        }
    }

    /**
     * Add exclude target by ASN
     */
    if (xconf->exclude_asn_v4) {
        if (xconf->as_query == NULL) {
            LOG(LEVEL_ERROR,
                "cannot add ipv4 exclude by ASN because no AS info loaded.\n");
            exit(1);
        }
        int err = targetset_add_asn_v4_string(&xconf->exclude, xconf->as_query,
                                              xconf->exclude_asn_v4);
        if (err) {
            LOG(LEVEL_ERROR, "add ipv4 exclude failed by ASN string.\n");
            exit(1);
        }
    }
    if (xconf->exclude_asn_v6) {
        if (xconf->as_query == NULL) {
            LOG(LEVEL_ERROR,
                "cannot add ipv6 exclude by ASN because no AS info loaded.\n");
            exit(1);
        }
        int err = targetset_add_asn_v6_string(&xconf->exclude, xconf->as_query,
                                              xconf->exclude_asn_v6);
        if (err) {
            LOG(LEVEL_ERROR, "add ipv6 exclude failed by ASN string.\n");
            exit(1);
        }
    }

    targetset_apply_excludes(&xconf->targets, &xconf->exclude);

    /* Optimize target selection so it's a quick binary search instead
     * of walking large memory tables. When we scan the entire Internet
     * our --excludefile will chop up our pristine 0.0.0.0/0 range into
     * hundreds of subranges. This allows us to grab addresses faster. */
    targetset_optimize(&xconf->targets);

    switch (xconf->op) {
        case Operation_Default:
            xconf_print_usage();
            break;

        case Operation_Scan:
            _main_scan(xconf);
            break;

        case Operation_Echo:
            xconf_echo(xconf, stdout);
            break;

        case Operation_DebugIF:
            rawsock_selftest_if(xconf->nic.ifname);
            break;

        case Operation_ListCidr:
            xconf_echo_cidr(xconf, stdout);
            break;

        case Operation_ListRange:
            list_range(xconf);
            break;

        case Operation_ListTargets:
            list_ip_port(xconf);
            return 0;

        case Operation_ListAdapters:
            rawsock_list_adapters();
            break;

        case Operation_ListScanModules:
            list_all_scan_modules();
            break;

        case Operation_HelpScanModule:
            help_scan_module(xconf->scanner);
            break;

        case Operation_ListProbeModules:
            list_all_probe_modules();
            break;

        case Operation_HelpProbeModule:
            help_probe_module(xconf->probe);
            break;

        case Operation_ListOutputModules:
            list_all_output_modules();
            break;

        case Operation_HelpOutputModule:
            help_output_module(xconf->out_conf.output_module);
            break;

        case Operation_ListGenerateModules:
            list_all_generate_modules();
            break;

        case Operation_HelpGenerateModule:
            help_generate_module(xconf->generator);
            break;

        case Operation_PrintHelp:
            xconf_print_help();
            break;

        case Operation_PrintIntro:
            xconf_print_intro();
            break;

        case Operation_PrintVersion:
            xconf_print_version();
            break;

        case Operation_Selftest:
            xconf_selftest();
            break;

        case Operation_Benchmark:
            xconf_benchmark(XCONF_DFT_BLACKROCK_ROUNDS);
            break;

#ifndef NOT_FOUND_BSON
        case Operation_ParseBson:
            parse_bson_file(xconf->parse_bson_file);
            break;
#endif

#ifndef NOT_FOUND_MONGOC
        case Operation_StoreBson:
            store_bson_file(xconf->store_bson_file, xconf->mongodb_uri,
                            xconf->mongodb_db, xconf->mongodb_col,
                            xconf->mongodb_app);
            break;

        case Operation_StoreJson:
            store_json_file(xconf->store_json_file, xconf->mongodb_uri,
                            xconf->mongodb_db, xconf->mongodb_col,
                            xconf->mongodb_app);
            break;
#endif

#ifndef NOT_FOUND_PCRE2
        case Operation_ListNmapProbes:
            nmapservice_print_probes_by_file(xconf->nmap_file, stdout);
            break;
#endif
    }

    /*release as query*/
    as_query_destroy(xconf->as_query);

    /*close logger*/
    LOG_close();

    return 0;
}

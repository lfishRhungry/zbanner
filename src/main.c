/*

    main

    This includes:

    * main()
    * transmit_thread() - transmits probe packets
    * receive_thread() - receives response packets

    You'll be wanting to study the transmit/receive threads, because that's
    where all the action is.

    This is the lynch-pin of the entire program, so it includes a heckuva lot
    of headers, and the functions have a lot of local variables. I'm trying
    to make this file relative "flat" this way so that everything is visible.
*/
#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>

#include "xconf.h"
#include "globals.h"       /* all the global variables in the program */
#include "transmit.h"
#include "receive.h"
#include "xtatus.h"        /* printf() regular status updates */
#include "cookie.h"         /* for SYN-cookies on send */
#include "version.h"

#include "stub/stub-pcap.h"          /* dynamically load libpcap library */
#include "smack/smack.h"              /* Aho-corasick state-machine pattern-matcher */
#include "nmap-service/read-service-probes.h"

#include "massip/massip-parse.h"
#include "massip/massip-port.h"

#include "templ/templ-init.h"          /* packet template, that we use to send */
#include "templ/templ-payloads.h"     /* UDP packet payloads */

#include "rawsock/rawsock.h"            /* API on top of Linux, Windows, Mac OS X*/
#include "rawsock/rawsock-adapter.h"    /* Get Ethernet adapter configuration */
#include "rawsock/rawsock-pcapfile.h"   /* for saving pcap files w/ raw packets */

#include "stack/stack-ndpv6.h"        /* IPv6 Neighbor Discovery Protocol */
#include "stack/stack-arpv4.h"        /* Handle ARP resolution and requests */

#include "pixie/pixie-timer.h"        /* portable time functions */
#include "pixie/pixie-threads.h"      /* portable threads */
#include "pixie/pixie-backtrace.h"    /* maybe print backtrace on crash */

#include "crypto/crypto-siphash24.h"   /* hash function, for hash tables */
#include "crypto/crypto-blackrock.h"   /* the BlackRock shuffling func */
#include "crypto/crypto-lcg.h"         /* the LCG randomization func */
#include "crypto/crypto-base64.h"      /* base64 encode/decode */

#include "util/throttle.h"      /* rate limit */
#include "util/dedup.h"         /* ignore duplicate responses */
#include "util/ptrace.h"        /* for nmap --packet-trace feature */
#include "util/initadapter.h"
#include "util/readrange.h"
#include "util/listscan.h"
#include "util/logger.h"             /* adjust with -v command-line opt */
#include "util/rte-ring.h"           /* producer/consumer ring buffer */
#include "util/rstfilter.h"
#include "util/mas-malloc.h"
#include "util/checksum.h"

#if defined(WIN32)
#include <WinSock.h>
#if defined(_MSC_VER)
#pragma comment(lib, "Ws2_32.lib")
#endif
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

/*
 * yea I know globals suck
 */
unsigned volatile is_tx_done = 0;
unsigned volatile is_rx_done = 0;

time_t global_now;

uint64_t usec_start;

/**
 * This is for some wrappered functions that use TemplateSet to create packets.
 * Do not modify it unless you know what u are doing.
*/
struct TemplateSet *global_tmplset;

/***************************************************************************
 * We trap the <ctrl-c> so that instead of exiting immediately, we sit in
 * a loop for a few seconds waiting for any late response. But, the user
 * can press <ctrl-c> a second time to exit that waiting.
 ***************************************************************************/
static void control_c_handler(int x)
{
    static unsigned control_c_pressed = 0;
    if (control_c_pressed == 0) {
        /*First time of <ctrl-c>*/
        fprintf(stderr,
                "waiting several seconds to exit..."
                "                                                            \n"
                );
        fflush(stderr);
        control_c_pressed++;
        /*Make xtate change into waiting status*/
        is_tx_done = 1;
    } else {

        if (is_rx_done) {
            /*Rx thread is being exiting after being told `is_rx_done`*/
            fprintf(stderr, "\nERROR: Rx Thread is still running\n");
            if (is_rx_done++ > 1)
                exit(1);
        } else {
            /*Second time of <ctrl-c>*/
            /*tell Rx thread to exit*/
            is_rx_done = 1;
        }
    }

}




/***************************************************************************
 * Called from main() to initiate the scan.
 * Launches the 'transmit_thread()' and 'receive_thread()' and waits for
 * them to exit.
 ***************************************************************************/
static int
main_scan(struct Xconf *xconf)
{
    /*We could have many tx threads but one rx thread*/
    struct TxThread    *tx_thread;
    struct RxThread     rx_thread[1];
    struct TemplateSet  tmplset;
    struct FTable       ft_table;
    uint64_t            count_ips;
    uint64_t            count_ports;
    uint64_t            range;
    unsigned            index;
    struct Xtatus       status;
    uint64_t            min_index = UINT64_MAX;
    time_t              now = time(0);


    memset(rx_thread, 0, sizeof(struct RxThread));
    tx_thread = CALLOC(xconf->tx_thread_count, sizeof(struct TxThread));

    
    /*
     * Initialize the task size
     */
    count_ips = rangelist_count(&xconf->targets.ipv4) + range6list_count(&xconf->targets.ipv6).lo;
    if (count_ips == 0) {
        LOG(0, "FAIL: target IP address list empty\n");
        LOG(0, " [hint] try something like \"--range 10.0.0.0/8\"\n");
        LOG(0, " [hint] try something like \"--range 192.168.0.100-192.168.0.200\"\n");
        return 1;
    }
    count_ports = rangelist_count(&xconf->targets.ports);
    if (count_ports == 0) {
        LOG(0, "FAIL: no ports were specified\n");
        LOG(0, " [hint] try something like \"-p80,8000-9000\"\n");
        LOG(0, " [hint] try something like \"--ports 0-65535\"\n");
        return 1;
    }
    range = count_ips * count_ports;

    /*
     * If the IP address range is very big, then require the
     * user apply an exclude range
     */
    if (count_ips > 1000000000ULL && rangelist_count(&xconf->exclude.ipv4) == 0) {
        LOG(0, "FAIL: range too big, need confirmation\n");
        LOG(0, " [hint] to prevent accidents, at least one --exclude must be specified\n");
        LOG(0, " [hint] use \"--exclude 255.255.255.255\" as a simple confirmation\n");
        exit(1);
    }

    /*
     * trim the nmap UDP payloads down to only those ports we are using. This
     * makes lookups faster at high packet rates.
     */
    payloads_udp_trim(xconf->payloads.udp, &xconf->targets);
    payloads_oproto_trim(xconf->payloads.oproto, &xconf->targets);


#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

    /*
     * Turn the adapter on, and get the running configuration
     */
    if (initialize_adapter(xconf) != 0)
        exit(1);
    if (!xconf->nic.is_usable) {
        LOG(0, "FAIL: failed to detect IP of interface\n");
        LOG(0, " [hint] did you spell the name correctly?\n");
        LOG(0, " [hint] if it has no IP address, "
                "manually set with \"--adapter-ip 192.168.100.5\"\n");
        exit(1);
    }

    /*
        * Set the "source port" of everything we transmit.
        */
    if (xconf->nic.src.port.range == 0) {
        unsigned port = 40000 + now % 20000;
        xconf->nic.src.port.first = port;
        xconf->nic.src.port.last  = port + 16;
        xconf->nic.src.port.range = 16;
    }

    /**
     * create callback queue
     * TODO: Maybe more queue?
    */
    xconf->stack = stack_create(xconf->nic.source_mac,
        &xconf->nic.src, xconf->stack_buf_count);
    
    /**
     * create fast-timeout table
    */
    if (xconf->is_fast_timeout) {
        ft_init_table(&ft_table, xconf->ft_spec);
        xconf->ft_table = &ft_table;
    }

    /*
        * Initialize the TCP packet template. The way this works is that
        * we parse an existing TCP packet, and use that as the template for
        * scanning. Then, we adjust the template with additional features,
        * such as the IP address and so on.
        */
    xconf->tmplset = &tmplset;
    /*
        * Set TemplateSet to Global for some wrappered functions to create packet.
    */
    
    /* it should be set before template init*/
    if (xconf->tcp_init_window)
        template_set_tcp_syn_window_of_default(xconf->tcp_init_window);

    if (xconf->tcp_window)
        template_set_tcp_window_of_default(xconf->tcp_window);
    
    global_tmplset = &tmplset;
    template_packet_init(
                xconf->tmplset,
                xconf->nic.source_mac,
                xconf->nic.router_mac_ipv4,
                xconf->nic.router_mac_ipv6,
                xconf->payloads.udp,
                xconf->payloads.oproto,
                stack_if_datalink(xconf->nic.adapter),
                xconf->seed,
                xconf->templ_opts);

    if (xconf->nmap.ttl)
        template_set_ttl(xconf->tmplset, xconf->nmap.ttl);

    if (xconf->nic.is_vlan)
        template_set_vlan(xconf->tmplset, xconf->nic.vlan_id);


    /*
     * Choose a default ScanModule if not specified.
     * Wrong specification will be handled in SET_scan_module in xconf.c
     */
    if (!xconf->scan_module){
        xconf->scan_module = get_scan_module_by_name("tcpsyn");
        LOG(0, "[-] Default ScanModule `tcpsyn` is chosen because no ScanModule was specified.\n");
    }

    xconf->scan_module->args  = xconf->scan_module_args;
    xconf->scan_module->probe = xconf->probe_module;

    /*
     * Do global init for ScanModule
     */
    if (!xconf->scan_module->global_init_cb(xconf)) {

        LOG(0, "FAIL: errors happened in global init of ScanModule.\n");
        exit(1);
    }

    /*probemodule may not be set*/
    if (xconf->probe_module) {
        xconf->probe_module->args = xconf->probe_module_args;
    }

    /*
     * Do global init for probe
     */
    if (xconf->probe_module){
        if (!xconf->probe_module->global_init_cb(xconf)) {
            LOG(0, "FAIL: errors in ProbeModule global initializing\n");
            exit(1);
        }
    }

    /*
     * BPF filter
     * We set BPF filter for pcap at last to avoid the filter affect router-mac
     * getting by ARP.
     * And the filter string is combined from ProbeModule and user setting.
     */
    rawsock_set_filter(xconf->nic.adapter, xconf->scan_module->bpf_filter,
        xconf->bpf_filter);

    /*
    * trap <ctrl-c> to pause
    */
    signal(SIGINT, control_c_handler);


    /*
     * Prepare for tx threads
     */
    for (index=0; index<xconf->tx_thread_count; index++) {
        struct TxThread *parms    = &tx_thread[index];
        parms->xconf              = xconf;
        parms->tx_index           = index;
        parms->my_index           = xconf->resume.index;
        parms->done_transmitting  = 0;
        parms->thread_handle_xmit = 0;
    }
    /*
     * Prepare for rx threads
     */
    rx_thread->xconf              = xconf;
    rx_thread->done_receiving     = 0;
    rx_thread->thread_handle_recv = 0;
    /** needed for --packet-trace option so that we know when we started
     * the scan
     */
    rx_thread->pt_start = 1.0 * pixie_gettime() / 1000000.0;

    /*
     * Print helpful text
     */
    {
        char buffer[80];
        struct tm x;

        now = time(0);
        safe_gmtime(&x, &now);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S GMT", &x);
        LOG(0, "Starting "XTATE_FIRST_UPPER_NAME" " XTATE_VERSION " ("XTATE_GITHUB") at %s\n",
            buffer);

        //LOG(0, " -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth\n");
        LOG(0, "Initiating ScanModule: %s\n", xconf->scan_module->name);
        if (xconf->probe_module)
            LOG(0, "Initiating ProbeModule: %s\n", xconf->probe_module->name);
        LOG(0, "Scanning %u hosts [%u port%s/host]\n",
            (unsigned)count_ips, (unsigned)count_ports, (count_ports==1)?"":"s");
    }
    

    /*
     * Start all the threads
     */
    rx_thread->thread_handle_recv = pixie_begin_thread(receive_thread, 0, rx_thread);
    for (index=0; index<xconf->tx_thread_count; index++) {
        struct TxThread *parms = &tx_thread[index];
        parms->thread_handle_xmit = pixie_begin_thread(transmit_thread, 0, parms);
    }

    /*
     * Now wait for <ctrl-c> to be pressed OR for Tx Threads to exit.
     * Tx Threads can shutdown by themselves for finishing their tasks.
     * We also can use <ctrl-c> to make them exit early.
     * All controls are decided by global variable `is_tx_done`.
     */
    pixie_usleep(1000 * 100);
    LOG(1, "[+] waiting for threads to finish\n");
    xtatus_start(&status);
    status.is_infinite = xconf->is_infinite;
    while (!is_tx_done) {
        unsigned i;
        double rate              = 0;
        uint64_t total_successed = 0;
        uint64_t total_sent      = 0;


        /* Find the minimum index of all the threads */
        min_index = UINT64_MAX;
        for (i=0; i<xconf->tx_thread_count; i++) {
            struct TxThread *parms = &tx_thread[i];

            if (min_index > parms->my_index)
                min_index = parms->my_index;

            rate += parms->throttler->current_rate;

            if (parms->total_sent)
                total_sent += *parms->total_sent;
        }

        if (rx_thread->total_successed)
            total_successed = *rx_thread->total_successed;

        if (min_index >= range && !xconf->is_infinite) {
            /* Note: This is how we can tell the scan has ended */
            is_tx_done = 1;
        }

        /*
         * update screen about once per second with statistics,
         * namely packets/second.
         */
        xtatus_print(&status, min_index, range, rate,
            total_successed, total_sent,
            0, xconf->is_status_ndjson);

        /* Sleep for almost a second */
        pixie_mssleep(750);
    }

    /*
     * If we haven't completed the scan, then save the resume
     * information.
     */
    if (min_index < count_ips * count_ports) {
        xconf->resume.index = min_index;

        /* Write current settings to "paused.conf" so that the scan can be restarted */
        xconf_save_state(xconf);
    }



    /*
     * Now Tx Threads have breaked out the main loop of sending because of
     * `is_tx_done` and go into loop of `stack_flush_packets` before `is_rx_done`.
     * Rx Thread exits just by our setting of `is_rx_done` according to time
     * waiting.
     * So `is_rx_done` is the important signal both for Tx/Rx Thread to exit.
     */
    now = time(0);
    for (;;) {
        unsigned i;
        double rate = 0;
        uint64_t total_successed = 0;
        uint64_t total_sent = 0;


        /* Find the minimum index of all the threads */
        min_index = UINT64_MAX;
        for (i=0; i<xconf->tx_thread_count; i++) {
            struct TxThread *parms = &tx_thread[i];

            if (min_index > parms->my_index)
                min_index = parms->my_index;

            rate += parms->throttler->current_rate;

            if (parms->total_sent)
                total_sent += *parms->total_sent;
        }

        if (rx_thread->total_successed)
            total_successed = *rx_thread->total_successed;

        xtatus_print(&status, min_index, range, rate,
            total_successed, total_sent,
            xconf->wait - (time(0) - now),
            xconf->is_status_ndjson);

        if (time(0) - now >= xconf->wait /*no more waiting time*/
            || is_rx_done                /*too many <ctrl-c>*/
            ) {
            LOG(1, "[+] tell threads to exit...                    \n");
            is_rx_done = 1;
            break;
        }

        pixie_mssleep(250);
    }

    for (unsigned i=0; i<xconf->tx_thread_count; i++) {
        struct TxThread *parms = &tx_thread[i];
        pixie_thread_join(parms->thread_handle_xmit);
    }
    pixie_thread_join(rx_thread->thread_handle_recv);


    uint64_t usec_now = pixie_gettime();
    fprintf(stderr, "\n%u milliseconds elapsed\n", (unsigned)((usec_now - usec_start)/1000));

    /*
     * Now cleanup everything
     */
    xtatus_finish(&status);

    /**
     * Do close for ScanModule
    */
    xconf->scan_module->close_cb();

    /**
     * Do close for ProbeModule
    */
    if (xconf->probe_module) {
        xconf->probe_module->close_cb();
    }

    free(tx_thread);

    rawsock_close_adapter(xconf->nic.adapter);
    
    LOG(1, "[+] all threads have exited                    \n");

    return 0;
}




/***************************************************************************
 ***************************************************************************/
int main(int argc, char *argv[])
{
    struct Xconf xconf[1];
    int has_target_addresses = 0;
    int has_target_ports = 0;
    
    usec_start = pixie_gettime();
#if defined(WIN32)
    {WSADATA x; WSAStartup(0x101, &x);}
#endif

    global_now = time(0);

    /* Set system to report debug information on crash */
    {
        int is_backtrace = 1;
        for (unsigned i=1; i<(unsigned)argc; i++) {
            if (strcmp(argv[i], "--nobacktrace") == 0)
                is_backtrace = 0;
        }
        if (is_backtrace)
            pixie_backtrace_init(argv[0]);
    }
    
    /*
     * Initialize those defaults that aren't zero
     */
    memset(xconf, 0, sizeof(*xconf));

    //=================================================Define default params

    /* 14 rounds seem to give way better statistical distribution than 4 with a 
    very low impact on scan rate */
    xconf->blackrock_rounds     = 14;
    xconf->wait                 = 10; /* how long to wait for responses when done */
    xconf->max_rate             = 100.0; /* max rate = hundred packets-per-second */
    xconf->tx_thread_count      = 1;
    xconf->shard.one            = 1;
    xconf->shard.of             = 1;
    xconf->min_packet_size      = 60;
    xconf->payloads.udp         = payloads_udp_create();
    xconf->payloads.oproto      = payloads_oproto_create();
    xconf->dedup_win            = 1000000;
    xconf->ft_spec              = 5;
    /*default entries count of callback queue and packet buffer queue*/
    /**
     * Default entries count of callback queue and packet buffer queue.
     * Must be power of 2 and do not exceed the size limit of rte-ring.
    */
    xconf->stack_buf_count = 16384;


    /*
     * Read in the configuration from the command-line. We are looking for
     * either options or a list of IPv4 address ranges.
     */
    xconf_command_line(xconf, argc, argv);
    if (xconf->seed == 0)
        xconf->seed = get_one_entropy(); /* entropy for randomness */

    /*
     * Load database files like "nmap-payloads" and "nmap-service-probes"
     */
    load_database_files(xconf);

    /* We need to do a separate "raw socket" initialization step. This is
     * for Windows and PF_RING. */
    if (pcap_init() != 0)
        LOG(2, "libpcap: failed to load\n");
    rawsock_init();


    /*
     * Apply excludes. People ask us not to scan them, so we maintain a list
     * of their ranges, and when doing wide scans, add the exclude list to
     * prevent them from being scanned.
     */
    has_target_addresses =
        massip_has_ipv4_targets(&xconf->targets) || massip_has_ipv6_targets(&xconf->targets);
    has_target_ports = massip_has_target_ports(&xconf->targets);
    massip_apply_excludes(&xconf->targets, &xconf->exclude);
    if (!has_target_ports && xconf->op == Operation_ListTargets)
        massip_add_port_string(&xconf->targets, "80", 0);




    /* Optimize target selection so it's a quick binary search instead
     * of walking large memory tables. When we scan the entire Internet
     * our --excludefile will chop up our pristine 0.0.0.0/0 range into
     * hundreds of subranges. This allows us to grab addresses faster. */
    massip_optimize(&xconf->targets);
    
    /* FIXME: we only support 63-bit scans at the current time.
     * This is big enough for the IPv4 Internet, where scanning
     * for all TCP ports on all IPv4 addresses results in a 48-bit
     * scan, but this isn't big enough even for a single port on
     * an IPv6 subnet (which are 64-bits in size, usually). However,
     * even at millions of packets per second scanning rate, you still
     * can't complete a 64-bit scan in a reasonable amount of time.
     * Nor would you want to attempt the feat, as it would overload
     * the target IPv6 subnet. Since implementing this would be
     * difficult for 32-bit processors, for now, I'm going to stick
     * to a simple 63-bit scan.
     */
    if (massint128_bitcount(massip_range(&xconf->targets)) > 63) {
        fprintf(stderr, "[-] FAIL: scan range too large, max is 63-bits, requested is %u bits\n",
                massint128_bitcount(massip_range(&xconf->targets)));
        fprintf(stderr, "    Hint: scan range is number of IP addresses times number of ports\n");
        fprintf(stderr, "    Hint: IPv6 subnet must be at least /66 \n");
        exit(1);
    }

    /*
     * Once we've read in the configuration, do the operation that was
     * specified
     */
    switch (xconf->op) {
    case Operation_Default:
        /* Print usage info and exit */
        xconf_set_parameter(xconf, "usage", "true");
        break;

    case Operation_Scan:
        /*
         * THIS IS THE NORMAL THING
         */
        if (rangelist_count(&xconf->targets.ipv4) == 0 && massint128_is_zero(range6list_count(&xconf->targets.ipv6))) {
            /* We check for an empty target list here first, before the excludes,
             * so that we can differentiate error messages after excludes, in case
             * the user specified addresses, but they were removed by excludes. */
            LOG(0, "FAIL: target IP address list empty\n");
            if (has_target_addresses) {
                LOG(0, " [hint] all addresses were removed by exclusion ranges\n");
            } else {
                LOG(0, " [hint] try something like \"--range 10.0.0.0/8\"\n");
                LOG(0, " [hint] try something like \"--range 192.168.0.100-192.168.0.200\"\n");
            }
            exit(1);
        }
        if (rangelist_count(&xconf->targets.ports) == 0) {
            if (has_target_ports) {
                LOG(0, " [hint] all ports were removed by exclusion ranges\n");
                return 1;
            } else {
                LOG(0, "NOTE: no ports were specified, use default port TCP:80 .\n");
                LOG(0, " [hint] ignored if the ScanModule does not need port. (eg. icmp or arp)\n");
                LOG(0, " [hint] or try something like \"-p 80,8000-9000\"\n");
                massip_add_port_string(&xconf->targets, "80", 0);
            }
        }
        return main_scan(xconf);

    case Operation_ListTargets:
        /* Create a randomized list of IP addresses */
        listscan(xconf);
        return 0;

    case Operation_ListAdapters:
        /* List the network adapters we might want to use for scanning */
        rawsock_list_adapters();
        break;

    case Operation_ListRange:
        readrange(xconf);
        return 0;

    case Operation_Echo:
        xconf_echo(xconf, stdout);
        exit(0);
        break;

    case Operation_ListCidr:
        xconf_echo_cidr(xconf, stdout);
        exit(0);
        break;

    case Operation_ListProbeModules:
        list_all_probe_modules();
        break;
    
    case Operation_ListScanModules:
        list_all_scan_modules();
        break;
    
    case Operation_PrintHelp:
        xconf_print_help();
        break;
    }


    return 0;
}



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
#include "syn-cookie.h"         /* for SYN-cookies on send */

#include "out/output.h"             /* for outputting results */
#include "stub/stub-pcap.h"          /* dynamically load libpcap library */
#include "smack/smack.h"              /* Aho-corasick state-machine pattern-matcher */
#include "in/in-binary.h"          /* convert binary output to XML/JSON */
#include "vulncheck/vulncheck.h"          /* checking vulns like monlist, poodle, heartblee */
#include "scripting/scripting.h"
#include "nmap-service/read-service-probes.h"

#include "massip/massip-parse.h"
#include "massip/massip-port.h"

#include "templ/templ-pkt.h"          /* packet template, that we use to send */
#include "templ/templ-payloads.h"     /* UDP packet payloads */

#include "rawsock/rawsock.h"            /* API on top of Linux, Windows, Mac OS X*/
#include "rawsock/rawsock-adapter.h"    /* Get Ethernet adapter configuration */
#include "rawsock/rawsock-pcapfile.h"   /* for saving pcap files w/ raw packets */

#include "stack/stack-ndpv6.h"        /* IPv6 Neighbor Discovery Protocol */
#include "stack/stack-arpv4.h"        /* Handle ARP resolution and requests */
#include "stack/stack-tcp-core.h"          /* for TCP/IP connection table */

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

#include "proto/proto-x509.h"
#include "proto/proto-arp.h"          /* for responding to ARP requests */
#include "proto/proto-banner1.h"      /* for snatching banners from systems */
#include "proto/proto-preprocess.h"   /* quick parse of packets */
#include "proto/proto-icmp.h"         /* handle ICMP responses */
#include "proto/proto-udp.h"          /* handle UDP responses */
#include "proto/proto-snmp.h"         /* parse SNMP responses */
#include "proto/proto-ntp.h"          /* parse NTP responses */
#include "proto/proto-coap.h"         /* CoAP selftest */
#include "proto/proto-zeroaccess.h"
#include "proto/proto-sctp.h"
#include "proto/proto-oproto.h"       /* Other protocols on top of IP */

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

/***************************************************************************
 * We trap the <ctrl-c> so that instead of exiting immediately, we sit in
 * a loop for a few seconds waiting for any late response. But, the user
 * can press <ctrl-c> a second time to exit that waiting.
 ***************************************************************************/
static void control_c_handler(int x)
{
    static unsigned control_c_pressed = 0;
    static unsigned control_c_pressed_again = 0;
    if (control_c_pressed == 0) {
        fprintf(stderr,
                "waiting several seconds to exit..."
                "                                                            \n"
                );
        fflush(stderr);
        control_c_pressed = 1+x;
        is_tx_done = control_c_pressed;
    } else {
        if (is_rx_done) {
            fprintf(stderr, "\nERROR: threads not exiting %d\n", is_rx_done);
            if (is_rx_done++ > 1)
                exit(1);
        } else {
            control_c_pressed_again = 1;
            is_rx_done = control_c_pressed_again;
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
    struct TxThread *tx_thread;
    struct RxThread rx_thread[1];
    struct TemplateSet tmplset;
    uint64_t count_ips;
    uint64_t count_ports;
    uint64_t range;
    unsigned index;
    time_t now = time(0);
    struct Xtatus status;
    uint64_t min_index = UINT64_MAX;
    struct MassVulnCheck *vulncheck = NULL;


    memset(rx_thread, 0, sizeof(struct RxThread));
    tx_thread = CALLOC(xconf->tx_thread_count, sizeof(struct TxThread));

    /*
     * Vuln check initialization
     */
    if (xconf->vuln_name) {
        unsigned i;
		unsigned is_error;
        vulncheck = vulncheck_lookup(xconf->vuln_name);
        
        /* If no ports specified on command-line, grab default ports */
        is_error = 0;
        if (rangelist_count(&xconf->targets.ports) == 0)
            rangelist_parse_ports(&xconf->targets.ports, vulncheck->ports, &is_error, 0);
        
        /* Kludge: change normal port range to vulncheck range */
        for (i=0; i<xconf->targets.ports.count; i++) {
            struct Range *r = &xconf->targets.ports.list[i];
            r->begin = (r->begin&0xFFFF) | Templ_VulnCheck;
            r->end = (r->end & 0xFFFF) | Templ_VulnCheck;
        }
    }
    
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
    range += (uint64_t)(xconf->retries * range);

    /*
     * If doing an ARP scan, then don't allow port scanning
     */
    if (rangelist_is_contains(&xconf->targets.ports, Templ_ARP)) {
        if (xconf->targets.ports.count != 1) {
            LOG(0, "FAIL: cannot arpscan and portscan at the same time\n");
            return 1;
        }
    }

    /*
     * If the IP address range is very big, then require that that the
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

    /*
     * Do global init for stateless probe
     */
    if (xconf->stateless_probe && xconf->stateless_probe->global_init){
        if (EXIT_FAILURE == xconf->stateless_probe->global_init(xconf)) {
            LOG(0, "FAIL: errors in stateless probe global initializing\n");
            exit(1);
        }
    }


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
        * Initialize the TCP packet template. The way this works is that
        * we parse an existing TCP packet, and use that as the template for
        * scanning. Then, we adjust the template with additional features,
        * such as the IP address and so on.
        */
    xconf->tmplset = &tmplset;
    xconf->tmplset->vulncheck = vulncheck;
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

    /*
        * Set the "source port" of everything we transmit.
        */
    if (xconf->nic.src.port.range == 0) {
        unsigned port = 40000 + now % 20000;
        xconf->nic.src.port.first = port;
        xconf->nic.src.port.last = port + 16;
        xconf->nic.src.port.range = 16;
    }

    /*
        * Set the "TTL" (IP time-to-live) of everything we send.
        */
    if (xconf->nmap.ttl)
        template_set_ttl(xconf->tmplset, xconf->nmap.ttl);

    if (xconf->nic.is_vlan)
        template_set_vlan(xconf->tmplset, xconf->nic.vlan_id);

    /**
     * create callback queue
     * TODO: Maybe more queue?
    */
    xconf->stack = stack_create(xconf->nic.source_mac,
        &xconf->nic.src, xconf->stack_buf_count);

    /*
        * trap <ctrl-c> to pause
        */
    signal(SIGINT, control_c_handler);


    /*
     * Prepare for tx threads
     */
    for (index=0; index<xconf->tx_thread_count; index++) {
        struct TxThread *parms = &tx_thread[index];
        parms->xconf = xconf;
        parms->tx_index = index;
        parms->my_index = xconf->resume.index;
        parms->done_transmitting = 0;
        parms->thread_handle_xmit = 0;
    }
    /*
     * Prepare for rx threads
     */
    rx_thread->xconf = xconf;
    rx_thread->done_receiving = 0;
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

        if (count_ports == 1 && \
            xconf->targets.ports.list->begin == Templ_ICMP_echo && \
            xconf->targets.ports.list->end == Templ_ICMP_echo)
            { /* ICMP only */
                //LOG(0, " -- forced options: -sn -n --randomize-hosts -v --send-eth\n");
                LOG(0, "Initiating ICMP Echo Scan\n");
                LOG(0, "Scanning %u hosts\n",(unsigned)count_ips);
             }
        else /* This could actually also be a UDP only or mixed UDP/TCP/ICMP scan */
            {
                //LOG(0, " -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth\n");
                LOG(0, "Initiating SYN Stealth Scan\n");
                LOG(0, "Scanning %u hosts [%u port%s/host]\n",
                    (unsigned)count_ips, (unsigned)count_ports, (count_ports==1)?"":"s");
            }
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
     * Now wait for <ctrl-c> to be pressed OR for threads to exit
     */
    pixie_usleep(1000 * 100);
    LOG(1, "[+] waiting for threads to finish\n");
    xtatus_start(&status);
    status.is_infinite = xconf->is_infinite;
    while (!is_tx_done && xconf->output.is_status_updates) {
        unsigned i;
        double rate = 0;
        uint64_t total_tcbs = 0;
        uint64_t total_synacks = 0;
        uint64_t total_syns = 0;
        uint64_t total_responsed = 0;


        /* Find the minimum index of all the threads */
        min_index = UINT64_MAX;
        for (i=0; i<xconf->tx_thread_count; i++) {
            struct TxThread *parms = &tx_thread[i];

            /*Just tx's my_index & rate are meaningful*/
            if (parms->thread_handle_xmit) {
                if (min_index > parms->my_index)
                    min_index = parms->my_index;

                rate += parms->throttler->current_rate;
            }

            if (parms->total_syns)
                total_syns += *parms->total_syns;
        }

        if (rx_thread->total_tcbs)
            total_tcbs = *rx_thread->total_tcbs;
        if (rx_thread->total_synacks)
            total_synacks = *rx_thread->total_synacks;
        if (rx_thread->total_responsed)
            total_responsed = *rx_thread->total_responsed;

        if (min_index >= range && !xconf->is_infinite) {
            /* Note: This is how we can tell the scan has ended */
            is_tx_done = 1;
        }

        /*
         * update screen about once per second with statistics,
         * namely packets/second.
         */
        if (xconf->output.is_status_updates)
            xtatus_print(&status, min_index, range, rate,
                total_tcbs, total_synacks, total_syns, total_responsed,
                0, xconf->output.is_status_ndjson);

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
     * Now wait for all threads to exit
     */
    now = time(0);
    for (;;) {
        unsigned tx_done_count = 0;
        unsigned i;
        double rate = 0;
        uint64_t total_tcbs = 0;
        uint64_t total_synacks = 0;
        uint64_t total_syns = 0;
        uint64_t total_responsed = 0;


        /* Find the minimum index of all the threads */
        min_index = UINT64_MAX;
        for (i=0; i<xconf->tx_thread_count; i++) {
            struct TxThread *parms = &tx_thread[i];

            /*Just tx's my_index & rate are meaningful*/
            if (parms->thread_handle_xmit) {
                if (min_index > parms->my_index)
                    min_index = parms->my_index;

                rate += parms->throttler->current_rate;
            }

            if (parms->total_syns)
                total_syns += *parms->total_syns;
        }

        if (rx_thread->total_tcbs)
            total_tcbs = *rx_thread->total_tcbs;
        if (rx_thread->total_synacks)
            total_synacks = *rx_thread->total_synacks;
        if (rx_thread->total_responsed)
            total_responsed = *rx_thread->total_responsed;

        if (time(0) - now >= xconf->wait) {
            is_rx_done = 1;
        }

        if (time(0) - now - 10 > xconf->wait) {
            LOG(0, "[-] Passed the wait window but still running, forcing exit...        \n");
            exit(0);
        }

        if (xconf->output.is_status_updates) {
            xtatus_print(&status, min_index, range, rate,
                total_tcbs, total_synacks, total_syns, total_responsed,
                xconf->wait - (time(0) - now),
                xconf->output.is_status_ndjson);

            for (i=0; i<xconf->tx_thread_count; i++) {
                struct TxThread *parms = &tx_thread[i];
                tx_done_count += parms->done_transmitting;
            }

            pixie_mssleep(250);

            if (tx_done_count < xconf->tx_thread_count)
                continue;
            is_tx_done = 1;
            if (!rx_thread->done_receiving)
                continue;
            is_rx_done = 1;

        } else {
            /* [AFL-fuzz]
             * Join the threads, which doesn't allow us to print out 
             * status messages, but allows us to exit cleanly without
             * any waiting */
            for (i=0; i<xconf->tx_thread_count; i++) {
                struct TxThread *parms = &tx_thread[i];

                if (parms->thread_handle_xmit) {
                    pixie_thread_join(parms->thread_handle_xmit);
                    parms->thread_handle_xmit = 0;
                }
            }
            if (rx_thread->thread_handle_recv) {
                pixie_thread_join(rx_thread->thread_handle_recv);
                rx_thread->thread_handle_recv = 0;
            }
            is_tx_done = 1;
            is_rx_done = 1;
        }

        break;
    }


    /*
     * Now cleanup everything
     */
    xtatus_finish(&status);

    if (!xconf->output.is_status_updates) {
        uint64_t usec_now = pixie_gettime();

        printf("%u milliseconds elapsed\n", (unsigned)((usec_now - usec_start)/1000));
    }

	/**
     * Do close for stateless probe
    */
    if (xconf->stateless_probe && xconf->stateless_probe->close) {
        xconf->stateless_probe->close(xconf);
    }

    free(tx_thread);
    
    LOG(1, "[+] all threads have exited                    \n");

    return 0;
}




/***************************************************************************
 ***************************************************************************/
int main(int argc, char *argv[])
{
    struct Xconf xconf[1];
    unsigned i;
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
        for (i=1; i<(unsigned)argc; i++) {
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
    xconf->blackrock_rounds = 14;
    xconf->output.is_show_open = 1; /* default: show syn-ack, not rst */
    xconf->output.is_status_updates = 1; /* default: show status updates */
    xconf->wait = 10; /* how long to wait for responses when done */
    xconf->max_rate = 100.0; /* max rate = hundred packets-per-second */
    xconf->tx_thread_count = 1;
    xconf->rx_thread_count = 1; /*receive thread num is always 1*/
    xconf->shard.one = 1;
    xconf->shard.of = 1;
    xconf->min_packet_size = 60;
    xconf->payloads.udp = payloads_udp_create();
    xconf->payloads.oproto = payloads_oproto_create();
    safe_strcpy(xconf->output.rotate.directory,
        sizeof(xconf->output.rotate.directory), ".");
    xconf->is_capture_cert = 1;
    xconf->dedup_win1 = 1000000;
    xconf->dedup_win2 = 1000000;
    /*default entries count of callback queue and packet buffer queue*/
    /**
     * Default entries count of callback queue and packet buffer queue.
     * Must be power of 2 and do not exceed the size limit of rte-ring.
    */
    xconf->stack_buf_count = 16384;

    /*
     * Pre-parse the command-line
     */
    if (xconf_contains("--readscan", argc, argv)) {
        xconf->is_readscan = 1;
    }

    /*
     * On non-Windows systems, read the defaults from the file in
     * the /etc directory. These defaults will contain things
     * like the output directory, max packet rates, and so on. Most
     * importantly, the master "--excludefile" might be placed here,
     * so that blacklisted ranges won't be scanned, even if the user
     * makes a mistake
     */
#if !defined(WIN32)
    if (!xconf->is_readscan) {
        if (access(XTATE_DEFAULT_CONF, 0) == 0) {
            xconf_set_parameter(xconf, "conf", XTATE_DEFAULT_CONF);
        }
    }
#endif

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

    /*
     * Load the scripting engine if needed and run those that were
     * specified.
     */
    if (xconf->is_scripting)
        scripting_init(xconf);

    /* We need to do a separate "raw socket" initialization step. This is
     * for Windows and PF_RING. */
    if (pcap_init() != 0)
        LOG(2, "libpcap: failed to load\n");
    rawsock_init();

    /* Init some protocol parser data structures */
    snmp_init();
    x509_init();


    /*
     * Apply excludes. People ask us not to scan them, so we maintain a list
     * of their ranges, and when doing wide scans, add the exclude list to
     * prevent them from being scanned.
     */
    has_target_addresses = massip_has_ipv4_targets(&xconf->targets) || massip_has_ipv6_targets(&xconf->targets);
    has_target_ports = massip_has_target_ports(&xconf->targets);
    massip_apply_excludes(&xconf->targets, &xconf->exclude);
    if (!has_target_ports && xconf->op == Operation_ListScan)
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
     * Choose a default StatelessProbe if not specified.
     * Wrong specification will be handled in SET_stateless_probe in main-conf.c
     */
    if (xconf->is_stateless_banners && !xconf->stateless_probe){
        xconf->stateless_probe = get_stateless_probe("null");
        LOG(0, "[-] Default NullProbe is chosen because no statelss-probe was specified.\n");
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
            } else {
                LOG(0, "FAIL: no ports were specified\n");
                LOG(0, " [hint] try something like \"-p80,8000-9000\"\n");
                LOG(0, " [hint] try something like \"--ports 0-65535\"\n");
            }
            return 1;
        }
        return main_scan(xconf);

    case Operation_ListScan:
        /* Create a randomized list of IP addresses */
        listscan(xconf);
        return 0;

    case Operation_List_Adapters:
        /* List the network adapters we might want to use for scanning */
        rawsock_list_adapters();
        break;

    case Operation_DebugIF:
        rawsock_selftest_if(xconf->nic.ifname);
        return 0;

    case Operation_ReadRange:
        readrange(xconf);
        return 0;

    case Operation_ReadScan:
        {
            unsigned start;
            unsigned stop;

            /* find first file */
            for (start=1; start<(unsigned)argc; start++) {
                if (memcmp(argv[start], "--readscan", 10) == 0) {
                    start++;
                    break;
                }
            }

            /* find last file */
            for (stop=start+1; stop<(unsigned)argc && argv[stop][0] != '-'; stop++)
                ;

            /*
             * read the binary files, and output them again depending upon
             * the output parameters
             */
            readscan_binary_scanfile(xconf, start, stop, argv);

        }
        break;

    case Operation_Benchmark:
        printf("=== benchmarking (%u-bits) ===\n\n", (unsigned)sizeof(void*)*8);
        blackrock_benchmark(xconf->blackrock_rounds);
        blackrock2_benchmark(xconf->blackrock_rounds);
        smack_benchmark();
        exit(1);
        break;

    case Operation_Echo:
        xconf_echo(xconf, stdout);
        exit(0);
        break;

    case Operation_EchoCidr:
        xconf_echo_cidr(xconf, stdout);
        exit(0);
        break;

    case Operation_Selftest:
        /*
         * Do a regression test of all the significant units
         */
        {
            int x = 0;
            extern int proto_isakmp_selftest(void);
            
            x += massip_selftest();
            x += ranges6_selftest();
            x += dedup_selftest();
            x += checksum_selftest();
            x += ipv6address_selftest();
            x += proto_coap_selftest();
            x += smack_selftest();
            x += sctp_selftest();
            x += base64_selftest();
            x += banner1_selftest();
            x += output_selftest();
            x += siphash24_selftest();
            x += ntp_selftest();
            x += snmp_selftest();
            x += proto_isakmp_selftest();
            x += templ_payloads_selftest();
            x += blackrock_selftest();
            x += rawsock_selftest();
            x += lcg_selftest();
            x += template_selftest();
            x += ranges_selftest();
            x += massip_parse_selftest();
            x += pixie_time_selftest();
            x += rte_ring_selftest();
            x += xconf_selftest();
            x += zeroaccess_selftest();
            x += nmapserviceprobes_selftest();
            x += rstfilter_selftest();
            x += masscan_app_selftest();


            if (x != 0) {
                /* one of the selftests failed, so return error */
                fprintf(stderr, "regression test: failed :( \n");
                return 1;
            } else {
                fprintf(stderr, "regression test: success!\n");
                return 0;
            }
        }
        break;
    
    case Operation_List_Probes:
        list_all_probes();
        break;
    }


    return 0;
}



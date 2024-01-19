#include "receive.h"

#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>

#include "xconf.h"
#include "globals.h"       /* all the global variables in the program */
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


/***************************************************************************
 ***************************************************************************/
// static unsigned
// is_nic_port(const struct Xconf *xconf, unsigned ip)
// {
//     if (is_my_port(&xconf->nic.src, ip))
//         return 1;
//     return 0;
// }

static unsigned
is_ipv6_multicast(ipaddress ip_me)
{
    /* If this is an IPv6 multicast packet, one sent to the IPv6
     * address with a prefix of FF02::/16 */
    return ip_me.version == 6 && (ip_me.ipv6.hi>>48ULL) == 0xFF02;
}

void
receive_thread(void *v)
{
    struct RxThread *parms = (struct RxThread *)v;
    const struct Xconf *xconf = parms->xconf;
    struct Adapter *adapter = xconf->nic.adapter;
    int data_link = stack_if_datalink(adapter);
    struct Output *out;
    struct DedupTable *dedup;
    struct DedupTable *dedup_for_stateless;
    struct PcapFile *pcapfile = NULL;
    struct TCP_ConnectionTable *tcpcon = 0;
    uint64_t *status_synack_count;
    uint64_t *status_tcb_count;
    uint64_t *status_responsed_count;
    uint64_t entropy = xconf->seed;
    struct ResetFilter *rf;
    struct stack_t *stack = xconf->stack;
    struct source_t src = {0};

    
    
    /* For reducing RST responses, see rstfilter_is_filter() below */
    rf = rstfilter_create(entropy, 16384);

    /* some status variables */
    status_synack_count = MALLOC(sizeof(uint64_t));
    *status_synack_count = 0;
    parms->total_synacks = status_synack_count;

    status_tcb_count = MALLOC(sizeof(uint64_t));
    *status_tcb_count = 0;
    parms->total_tcbs = status_tcb_count;

    status_responsed_count = MALLOC(sizeof(uint64_t));
    *status_responsed_count = 0;
    parms->total_responsed = status_responsed_count;

    LOG(1, "[+] starting receive thread\n");
    
    /* Lock threads to the CPUs one by one.
     * Tx threads follow  the only one Rx thread.
     */
    if (pixie_cpu_get_count() > 1) {
        pixie_cpu_set_affinity(0);
    }

    /*
     * If configured, open a --pcap file for saving raw packets. This is
     * so that we can debug scans, but also so that we can look at the
     * strange things people send us. Note that we don't record transmitted
     * packets, just the packets we've received.
     */
    if (xconf->pcap_filename[0]) {
        pcapfile = pcapfile_openwrite(xconf->pcap_filename, 1);
    }

    /*
     * Open output. This is where results are reported when saving
     * the --output-format to the --output-filename
     */
    out = output_create(xconf, 0);

    /*
     * Create deduplication table. This is so when somebody sends us
     * multiple responses, we only record the first one.
     */
    if (!xconf->is_nodedup1){
        dedup = dedup_create(xconf->dedup_win1);
    }else{
        dedup = NULL;
    }

    /*
     * Create deduplication table for stateless-banners mode.
     * This is so when somebody sends us multiple app-layer responses,
     * we only record the first one.
     */
    if (xconf->is_stateless_banners && !xconf->is_nodedup2){
        dedup_for_stateless = dedup_create(xconf->dedup_win2);
    }else{
        dedup_for_stateless = NULL;
    }

    /*
     * Do thread init for stateless probe
     */
    if (xconf->stateless_probe && xconf->stateless_probe->thread_init){
        xconf->stateless_probe->thread_init(parms);
    }



    /*
     * Create a TCP connection table (per rx thread) for interacting with live
     * connections when doing --banners
     */
    if (xconf->is_banners) {
        struct TcpCfgPayloads *pay;
        size_t i;

        /*
         * Create TCP connection table
         */
        tcpcon = tcpcon_create_table(
            (size_t)(xconf->max_rate/5),
            stack,
            &xconf->tmplset->pkts[Proto_TCP],
            output_report_banner,
            out,
            xconf->tcb.timeout,
            xconf->seed
            );
        
        /*
         * Initialize TCP scripting
         */
        scripting_init_tcp(tcpcon, xconf->scripting.L);

        /*
         * Get the possible source IP addresses and ports that xconf
         * might be using to transmit from.
         */
        adapter_get_source_addresses(xconf, &src);
                               

        /*
         * Set some flags [kludge]
         */
        tcpcon_set_banner_flags(tcpcon,
                xconf->is_capture_cert,
                xconf->is_capture_servername,
                xconf->is_capture_html,
                xconf->is_capture_heartbleed,
				xconf->is_capture_ticketbleed);
        if (xconf->is_hello_smbv1)
            tcpcon_set_parameter(tcpcon, "hello", 1, "smbv1");
        if (xconf->is_hello_http)
            tcpcon_set_parameter(tcpcon, "hello", 1, "http");
        if (xconf->is_hello_ssl)
            tcpcon_set_parameter(tcpcon, "hello", 1, "ssl");
        if (xconf->is_heartbleed)
            tcpcon_set_parameter(tcpcon, "heartbleed", 1, "1");
        if (xconf->is_ticketbleed)
            tcpcon_set_parameter(tcpcon, "ticketbleed", 1, "1");
        if (xconf->is_poodle_sslv3)
            tcpcon_set_parameter(tcpcon, "sslv3", 1, "1");

        if (xconf->http.payload)
            tcpcon_set_parameter(   tcpcon,
                                    "http-payload",
                                    xconf->http.payload_length,
                                    xconf->http.payload);
        if (xconf->http.user_agent)
            tcpcon_set_parameter(   tcpcon,
                                    "http-user-agent",
                                    xconf->http.user_agent_length,
                                    xconf->http.user_agent);
        if (xconf->http.host)
            tcpcon_set_parameter(   tcpcon,
                                    "http-host",
                                    xconf->http.host_length,
                                    xconf->http.host);
        if (xconf->http.method)
            tcpcon_set_parameter(   tcpcon,
                                    "http-method",
                                    xconf->http.method_length,
                                    xconf->http.method);
        if (xconf->http.url)
            tcpcon_set_parameter(   tcpcon,
                                    "http-url",
                                    xconf->http.url_length,
                                    xconf->http.url);
        if (xconf->http.version)
            tcpcon_set_parameter(   tcpcon,
                                    "http-version",
                                    xconf->http.version_length,
                                    xconf->http.version);


        if (xconf->tcp_connection_timeout) {
            char foo[64];
            snprintf(foo, sizeof(foo), "%u", xconf->tcp_connection_timeout);
            tcpcon_set_parameter(   tcpcon,
                                 "timeout",
                                 strlen(foo),
                                 foo);
        }
        if (xconf->tcp_hello_timeout) {
            char foo[64];
            snprintf(foo, sizeof(foo), "%u", xconf->tcp_hello_timeout);
            tcpcon_set_parameter(   tcpcon,
                                 "hello-timeout",
                                 strlen(foo),
                                 foo);
        }
        
        for (i=0; i<xconf->http.headers_count; i++) {
            tcpcon_set_http_header(tcpcon,
                        xconf->http.headers[i].name,
                        xconf->http.headers[i].value_length,
                        xconf->http.headers[i].value,
                        http_field_replace);
        }
        for (i=0; i<xconf->http.cookies_count; i++) {
            tcpcon_set_http_header(tcpcon,
                        "Cookie",
                        xconf->http.cookies[i].value_length,
                        xconf->http.cookies[i].value,
                        http_field_add);
        }
        for (i=0; i<xconf->http.remove_count; i++) {
            tcpcon_set_http_header(tcpcon,
                        xconf->http.headers[i].name,
                        0,
                        0,
                        http_field_remove);
        }

        for (pay = xconf->payloads.tcp; pay; pay = pay->next) {
            char name[64];
            snprintf(name, sizeof(name), "hello-string[%u]", pay->port);
            tcpcon_set_parameter(   tcpcon, 
                                    name, 
                                    strlen(pay->payload_base64), 
                                    pay->payload_base64);
        }

    }

    /*
     * In "offline" mode, we don't have any receive threads, so simply
     * wait until transmitter thread is done then go to the end
     */
    if (xconf->is_offline) {
        while (!is_rx_done)
            pixie_usleep(10000);
        parms->done_receiving = 1;
        goto end;
    }

    /*
     * Receive packets. This is where we catch any responses and print
     * them to the terminal.
     */
    LOG(2, "[+] THREAD: recv: starting main loop\n");
    while (!is_rx_done) {
        int status;
        unsigned length;
        unsigned secs;
        unsigned usecs;
        const unsigned char *px;
        int err;
        unsigned x;
        struct PreprocessedInfo parsed;
        ipaddress ip_me;
        unsigned port_me;
        ipaddress ip_them;
        unsigned port_them;
        unsigned seqno_me;
        unsigned seqno_them;
        unsigned win_them;
        unsigned cookie;
        unsigned Q = 0;

        /*
         * RECEIVE
         *
         * This is the boring part of actually receiving a packet
         */
        err = rawsock_recv_packet(
                    adapter,
                    &length,
                    &secs,
                    &usecs,
                    &px);
        if (err != 0) {
            if (tcpcon)
                tcpcon_timeouts(tcpcon, (unsigned)time(0), 0);
            continue;
        }
        

        /*
         * Do any TCP event timeouts based on the current timestamp from
         * the packet. For example, if the connection has been open for
         * around 10 seconds, we'll close the connection. (--banners)
         */
        if (tcpcon) {
            tcpcon_timeouts(tcpcon, secs, usecs);
        }

        if (length > 1514)
            continue;

        /*
         * "Preprocess" the response packet. This means to go through and
         * figure out where the TCP/IP headers are and the locations of
         * some fields, like IP address and port numbers.
         */
        x = preprocess_frame(px, length, data_link, &parsed);
        if (!x)
            continue; /* corrupt packet */
        ip_me = parsed.dst_ip;
        ip_them = parsed.src_ip;
        port_me = parsed.port_dst;
        port_them = parsed.port_src;
        seqno_them = TCP_SEQNO(px, parsed.transport_offset);
        seqno_me = TCP_ACKNO(px, parsed.transport_offset);
        win_them = TCP_WIN(px, parsed.transport_offset);
        
        assert(ip_me.version != 0);
        assert(ip_them.version != 0);

        switch (parsed.ip_protocol) {
        case 132: /* SCTP */
            cookie = syn_cookie(ip_them, port_them | (Proto_SCTP<<16), ip_me, port_me, entropy) & 0xFFFFFFFF;
            break;
        default:
            cookie = syn_cookie(ip_them, port_them, ip_me, port_me, entropy) & 0xFFFFFFFF;
        }

        /* verify: my IP address */
        if (!is_my_ip(stack->src, ip_me)) {
            /* NDP Neighbor Solicitations don't come to our IP address, but to
             * a multicast address */
            if (is_ipv6_multicast(ip_me)) {
                if (parsed.found == FOUND_NDPv6 && parsed.opcode == 135) {
                    stack_ndpv6_incoming_request(stack, &parsed, px, length);
                }
            }
            continue;
        }

        /*
         * Handle non-TCP protocols
         */
        switch (parsed.found) {
            case FOUND_NDPv6:
                switch (parsed.opcode) {
                case 133: /* Router Solicitation */
                    /* Ignore router solicitations, since we aren't a router */
                    continue;
                case 134: /* Router advertisement */
                    /* TODO: We need to process router advertisements while scanning
                     * so that we can print warning messages if router information
                     * changes while scanning. */
                    continue;
                case 135: /* Neighbor Solicitation */
                    /* When responses come back from our scans, the router will send us
                     * these packets. We need to respond to them, so that the router
                     * can then forward the packets to us. If we don't respond, we'll
                     * get no responses. */
                    stack_ndpv6_incoming_request(stack, &parsed, px, length);
                    continue;
                case 136: /* Neighbor Advertisement */
                    /* TODO: If doing an --ndpscan, the scanner subsystem needs to deal
                     * with these */
                    continue;
                case 137: /* Redirect */
                    /* We ignore these, since we really don't have the capability to send
                     * packets to one router for some destinations and to another router
                     * for other destinations */
                    continue;
                default:
                    break;
                }
                continue;
            case FOUND_ARP:
                LOGip(2, ip_them, 0, "-> ARP [%u] \n", px[parsed.found_offset]);

                switch (parsed.opcode) {
                case 1: /* request */
                    /* This function will transmit a "reply" to somebody's ARP request
                     * for our IP address (as part of our user-mode TCP/IP).
                     * Since we completely bypass the TCP/IP stack, we  have to handle ARPs
                     * ourself, or the router will lose track of us.*/
                     stack_arp_incoming_request(stack,
                                      ip_me.ipv4,
                                      xconf->nic.source_mac,
                                      px, length);
                    break;
                case 2: /* response */
                    /* This is for "arp scan" mode, where we are ARPing targets rather
                     * than port scanning them */

                    /* If we aren't doing an ARP scan, then ignore ARP responses */
                    if (!xconf->scan_type.arp)
                        break;

                    /* If this response isn't in our range, then ignore it */
                    if (!rangelist_is_contains(&xconf->targets.ipv4, ip_them.ipv4))
                        break;

                    /* Ignore duplicates */
                    if (!xconf->is_nodedup1){
                        if (dedup_is_duplicate(dedup, ip_them, 0, ip_me, 0))
                            continue;
                    }

                    /* ...everything good, so now report this response */
                    arp_recv_response(out, secs, px, length, &parsed);
                    break;
                }
                continue;
            case FOUND_UDP:
            case FOUND_DNS:
                if (!is_my_port(&xconf->nic.src, port_me))
                    continue;
                if (parms->xconf->nmap.packet_trace)
                    packet_trace(stdout, parms->pt_start, px, length, 0);
                handle_udp(out, secs, px, length, &parsed, entropy);
                continue;
            case FOUND_ICMP:
                handle_icmp(out, secs, px, length, &parsed, entropy);
                continue;
            case FOUND_SCTP:
                handle_sctp(out, secs, px, length, cookie, &parsed, entropy);
                break;
            case FOUND_OPROTO: /* other IP proto */
                handle_oproto(out, secs, px, length, &parsed, entropy);
                break;
            case FOUND_TCP:
                /* fall down to below */
                break;
            default:
                continue;
        }


        /* verify: my port number */
        if (!is_my_port(stack->src, port_me))
            continue;
        if (parms->xconf->nmap.packet_trace)
            packet_trace(stdout, parms->pt_start, px, length, 0);

        Q = 0;

        /* Save raw packet in --pcap file */
        if (pcapfile) {
            pcapfile_writeframe(
                pcapfile,
                px,
                length,
                length,
                secs,
                usecs);
        }

        {
            char buf[64];
            LOGip(5, ip_them, port_them, "-> TCP ackno=0x%08x flags=0x%02x(%s)\n",
                seqno_me,
                TCP_FLAGS(px, parsed.transport_offset),
                reason_string(TCP_FLAGS(px, parsed.transport_offset), buf, sizeof(buf)));
        }

        /* If recording --banners, create a new "TCP Control Block (TCB)" */
        if (tcpcon) {
            struct TCP_Control_Block *tcb;

            /* does a TCB already exist for this connection? */
            tcb = tcpcon_lookup_tcb(tcpcon,
                            ip_me, ip_them,
                            port_me, port_them);

            if (TCP_IS_SYNACK(px, parsed.transport_offset)) {
                if (cookie != seqno_me - 1) {
                    ipaddress_formatted_t fmt = ipaddress_fmt(ip_them);
                    LOG(2, "%s - bad cookie: ackno=0x%08x expected=0x%08x\n",
                        fmt.string, seqno_me-1, cookie);
                    continue;
                }
                if (tcb == NULL) {
                    tcb = tcpcon_create_tcb(tcpcon,
                                    ip_me, ip_them,
                                    port_me, port_them,
                                    seqno_me, seqno_them+1,
                                    parsed.ip_ttl, NULL,
                                    secs, usecs);
                    (*status_tcb_count)++;
                }
                Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_SYNACK,
                    0, 0, secs, usecs, seqno_them+1, seqno_me);

            } else if (tcb) {
                /* If this is an ACK, then handle that first */
                if (TCP_IS_ACK(px, parsed.transport_offset)) {
                    Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_ACK,
                        0, 0, secs, usecs, seqno_them, seqno_me);
                }

                /* If this contains payload, handle that second */
                if (parsed.app_length) {
                    Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_DATA,
                        px + parsed.app_offset, parsed.app_length,
                        secs, usecs, seqno_them, seqno_me);
                }

                /* If this is a FIN, handle that. Note that ACK +
                 * payload + FIN can come together */
                if (TCP_IS_FIN(px, parsed.transport_offset)
                    && !TCP_IS_RST(px, parsed.transport_offset)) {
                    Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_FIN,
                            0, 0, 
                            secs, usecs, 
                            seqno_them + parsed.app_length, /* the FIN comes after any data in the packet */
                            seqno_me);
                }

                /* If this is a RST, then we'll be closing the connection */
                if (TCP_IS_RST(px, parsed.transport_offset)) {
                    Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_RST,
                        0, 0, secs, usecs, seqno_them, seqno_me);
                }
            } else if (TCP_IS_FIN(px, parsed.transport_offset)) {
                ipaddress_formatted_t fmt;
                /*
                 * NO TCB!
                 *  This happens when we've sent a FIN, deleted our connection,
                 *  but the other side didn't get the packet.
                 */
                fmt = ipaddress_fmt(ip_them);
                LOG(4, "%s: received FIN but no TCB\n", fmt.string);
                if (TCP_IS_RST(px, parsed.transport_offset))
                    ; /* ignore if it's own TCP flag is set */
                else {
                    int is_suppress;
                    
                    is_suppress = rstfilter_is_filter(rf, ip_me, port_me, ip_them, port_them);
                    if (!is_suppress)
                        tcpcon_send_RST(
                            tcpcon,
                            ip_me, ip_them,
                            port_me, port_them,
                            seqno_them, seqno_me);
                }
            }

        }

        if (Q == 0)
            ; //printf("\nerr\n");
   
        if (TCP_IS_SYNACK(px, parsed.transport_offset)
            || TCP_IS_RST(px, parsed.transport_offset)) {

            /* figure out the status */
            status = PortStatus_Unknown;

            if (TCP_IS_SYNACK(px, parsed.transport_offset)) {

                /* verify syn-cookies for syn-ack*/
                if (cookie != seqno_me - 1) {
                    ipaddress_formatted_t fmt = ipaddress_fmt(ip_them);
                    LOG(2, "%s - bad syn-ack cookie: ackno=0x%08x expected=0x%08x\n",
                        fmt.string, seqno_me-1, cookie);
                    continue;
                }

                status = PortStatus_Open;

                /*care the zero win in SYNACK*/
                if (win_them==0) {
                    status = PortStatus_ZeroWin;
                }
            }

            if (TCP_IS_RST(px, parsed.transport_offset)) {

                /**
                 * verify syn-cookies for rst
                 * NOTE: diff from handling syn-ack
                */
                if (cookie != seqno_me - 1 && cookie != seqno_me) {
                    ipaddress_formatted_t fmt = ipaddress_fmt(ip_them);
                    LOG(2, "%s - bad rst cookie: ackno=0x%08x expected=0x%08x\n",
                        fmt.string, seqno_me-1, cookie);
                    continue;
                }

                status = PortStatus_Closed;
            }

            /* verify: ignore duplicates */
            if (!xconf->is_nodedup1){
                if (dedup_is_duplicate(dedup, ip_them, port_them, ip_me, port_me))
                    continue;
            }

            /*keep statistics after dedup*/
            if (TCP_IS_SYNACK(px, parsed.transport_offset)) {
                (*status_synack_count)++;
            }

            /* Send ACK with req in stateless-banners mode*/
            if (xconf->is_stateless_banners
                && TCP_IS_SYNACK(px, parsed.transport_offset)
                && status == PortStatus_Open) {

                unsigned char payload[STATELESS_PAYLOAD_MAX_LEN];
                size_t payload_len;
                payload_len = xconf->stateless_probe->make_payload(
                    ip_them, ip_me, port_them, port_me,
                    payload, STATELESS_PAYLOAD_MAX_LEN);
                
                tcp_send_ACK(
                    &xconf->tmplset->pkts[Proto_TCP],
                    stack,
                    ip_them, ip_me,
                    port_them, port_me,
                    seqno_them+1, seqno_me,
                    payload, payload_len);
            }

            /*
             * This is where we do the output
             */
            output_report_status(out, global_now, status, ip_them,
                        6, /* ip proto = tcp */ port_them,
                        px[parsed.transport_offset + 13], /* tcp flags */
                        parsed.ip_ttl, parsed.mac_src,
                        /* these are for feeding LZR*/
                        ip_me, port_me, seqno_them, seqno_me, win_them);
            

            /*
             * Send RST if no more connecting
             */
            if (tcpcon == NULL && !xconf->is_noreset1) {
                if (xconf->is_stateless_banners) {
                    if (status == PortStatus_ZeroWin)
                        tcp_send_RST(
                            &xconf->tmplset->pkts[Proto_TCP],
                            stack,
                            ip_them, ip_me,
                            port_them, port_me,
                            0, seqno_me);
                }else{
                    if (status == PortStatus_Open || status == PortStatus_ZeroWin)
                        tcp_send_RST(
                            &xconf->tmplset->pkts[Proto_TCP],
                            stack,
                            ip_them, ip_me,
                            port_them, port_me,
                            0, seqno_me);
                }
            }

            continue;

        }

        /*
         * We could recv Response DATA in different TCP flags:
         * 1.[ACK]
         * 2.[PSH, ACK]
         * 3.[FIN, PSH, ACK]
         * 
         * Because of different server or possible TCP retransmission.
         * 
         * Try to recv all possible Response DATA to
         * avoid packets lossing.
         * 
         * Note the verifying of cookies.
         */
        if (xconf->is_stateless_banners
            && TCP_IS_ACK(px, parsed.transport_offset)) {
            
            size_t had_sent = xconf->stateless_probe->get_payload_length(
                ip_them, ip_me, port_them, port_me);

            /* verify: ack-cookie*/
            if (cookie != (seqno_me - 1 - had_sent)) {
                ipaddress_formatted_t fmt = ipaddress_fmt(ip_them);
                LOG(2, "%s - bad ack cookie: ackno=0x%08x expected=0x%08x\n",
                    fmt.string, seqno_me-1, cookie+had_sent);
                continue;
            }
            
            /* verify: we need to output packet with response*/
            /* filter out ports that just ACK without data*/
            if (!parsed.app_length)
                continue;

            /* verify: ignore duplicates */
            if (!xconf->is_nodedup2){
                if (dedup_is_duplicate(dedup_for_stateless, ip_them, port_them, ip_me, port_me))
                    continue;
            }

            /* keep statistics on number responsed */
            (*status_responsed_count)++;

            output_report_status(
                        out,
                        global_now,
                        PortStatus_Responsed,
                        ip_them,
                        6, /* ip proto = tcp */
                        port_them,
                        px[parsed.transport_offset + 13], /* tcp flags */
                        parsed.ip_ttl,
                        parsed.mac_src
                        );
            
            /* output banner in stateless mode*/
            if (xconf->is_capture_stateless){
                unsigned char report_buf[STATELESS_BANNER_MAX_LEN];
                size_t report_len;

                report_len = xconf->stateless_probe->get_report_banner(
                    ip_them, ip_me, port_them, port_me,
                    &px[parsed.app_offset], parsed.app_length,
                    report_buf, STATELESS_BANNER_MAX_LEN);

                /*reduce useless output*/
                if (report_len>0)
                    output_report_banner(
                        out, global_now, ip_them, 6, port_them, PROTO_STATELESS,
                        parsed.ip_ttl, report_buf, report_len);
            }
            

            /*
             * Send RST after server's response
             */
            if (!xconf->is_noreset2)
                tcp_send_RST(
                    &xconf->tmplset->pkts[Proto_TCP],
                    stack,
                    ip_them, ip_me,
                    port_them, port_me,
                    seqno_them+had_sent, seqno_me);
        }
    }


    LOG(1, "[+] exiting receive thread                            \n");
    
    /*
     * cleanup
     */
end:
    if (tcpcon)
        tcpcon_destroy_table(tcpcon);
    if (!xconf->is_nodedup1){
        dedup_destroy(dedup);
    }
    if (xconf->is_stateless_banners && !xconf->is_nodedup2){
        dedup_destroy(dedup_for_stateless);
    }
    output_destroy(out);
    if (pcapfile)
        pcapfile_close(pcapfile);

    /*TODO: free stack packet buffers */

    /* Thread is about to exit */
    parms->done_receiving = 1;
}
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
#include "cookie.h"         /* for SYN-cookies on send */

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
    uint64_t *status_synack_count;
    uint64_t *status_responsed_count;
    uint64_t entropy = xconf->seed;
    struct stack_t *stack = xconf->stack;

    
    
    /* For reducing RST responses, see rstfilter_is_filter() below */
    // struct ResetFilter *rf;
    // rf = rstfilter_create(entropy, 16384);

    /* some status variables */
    status_synack_count = MALLOC(sizeof(uint64_t));
    *status_synack_count = 0;
    parms->total_synacks = status_synack_count;

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
            continue;
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
            cookie = get_cookie(ip_them, port_them | (Proto_SCTP<<16), ip_me, port_me, entropy) & 0xFFFFFFFF;
            break;
        default:
            cookie = get_cookie(ip_them, port_them, ip_me, port_me, entropy) & 0xFFFFFFFF;
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
            if (!xconf->is_noreset1) {
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
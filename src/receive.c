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

#include "output-modules/output-modules.h"
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
#include "stack/stack-queue.h"

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

// static unsigned
// is_ipv6_multicast(ipaddress ip_me)
// {
//     /* If this is an IPv6 multicast packet, one sent to the IPv6
//      * address with a prefix of FF02::/16 */
//     return ip_me.version == 6 && (ip_me.ipv6.hi>>48ULL) == 0xFF02;
// }

void
receive_thread(void *v)
{
    struct RxThread *parms = (struct RxThread *)v;
    const struct Xconf *xconf = parms->xconf;
    struct Adapter *adapter = xconf->nic.adapter;
    int data_link = stack_if_datalink(adapter);
    struct Output *out;
    struct DedupTable *dedup;
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
    if (!xconf->is_nodedup){
        dedup = dedup_create(xconf->dedup_win);
    }else{
        dedup = NULL;
    }

    /*
     * Do rx-thread init for ScanModule
     */
    if (xconf->scan_module->rx_thread_init_cb){
        if (SCAN_MODULE_INIT_FAILED ==
            xconf->scan_module->rx_thread_init_cb()) {
            LOG(0, "FAIL: errors happened in rx-thread init of ScanModule.\n");
            exit(1);
        }
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
        unsigned length;
        unsigned secs;
        unsigned usecs;
        const unsigned char *px;
        struct ScanModule *scan_module = xconf->scan_module;

        int err = rawsock_recv_packet(adapter, &length, &secs, &usecs, &px);
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
        struct PreprocessedInfo parsed;
        unsigned x = preprocess_frame(px, length, data_link, &parsed);
        if (!x)
            continue; /* corrupt packet */
        ipaddress ip_me = parsed.dst_ip;
        ipaddress ip_them = parsed.src_ip;
        unsigned port_me = parsed.port_dst;
        unsigned port_them = parsed.port_src;
        
        assert(ip_me.version != 0);
        assert(ip_them.version != 0);

        int is_myip = is_my_ip(stack->src, ip_me);
        int is_myport = is_my_port(stack->src, port_me);

        /**
         * callback funcs of ScanModule in rx-thread.
         * Step 1: Filter
        */
        if (scan_module->filter_packet_cb) {

            if (SCAN_MODULE_FILTER_OUT ==
                scan_module->filter_packet_cb(&parsed, entropy,
                    px, length, is_myip, is_myport)) {

                continue;
            }
        }

        if (parms->xconf->nmap.packet_trace)
            packet_trace(stdout, parms->pt_start, px, length, 0);

        /* Save raw packet in --pcap file */
        if (pcapfile) {
            pcapfile_writeframe(pcapfile, px, length, length, secs, usecs);
        }

        /**
         * callback funcs of ScanModule in rx-thread.
         * Step 2: Validate
        */
        if (scan_module->validate_packet_cb) {

            if (SCAN_MODULE_INVALID_PACKET ==
                scan_module->validate_packet_cb(&parsed, entropy,
                    px, length)) {

                        continue;
            }
        }

        /**
         * callback funcs of ScanModule in rx-thread.
         * Step 3: Dedup
        */
        if (scan_module->dedup_packet_cb && !xconf->is_nodedup) {

            unsigned dedup_type = SCAN_MODULE_DEFAULT_DEDUP_TYPE;

            if (SCAN_MODULE_DO_DEDUP ==
                scan_module->dedup_packet_cb(&parsed, entropy,
                    px, length, &dedup_type)) {

                if (dedup_is_duplicate(dedup, ip_them, port_them,
                        ip_me, port_me, dedup_type)) {
                    continue;
                }
            }
        }

        /**
         * callback funcs of ScanModule in rx-thread.
         * Step 4: Handle
        */
        unsigned need_response = SCAN_MODULE_NO_RESPONSE;
        unsigned successed = SCAN_MODULE_FAILURE_PACKET;
        char classification[SCAN_MODULE_CLS_LEN];
        char report[SCAN_MODULE_RPT_LEN];

        if (scan_module->handle_packet_cb) {
            need_response = scan_module->handle_packet_cb(&parsed, entropy,
                px, length, &successed,
                classification, SCAN_MODULE_CLS_LEN,
                report, SCAN_MODULE_RPT_LEN);
            
            output_tmp(&parsed, global_now, successed, classification, report);
        }

        /**
         * callback funcs of ScanModule in rx-thread.
         * Step 5: Response
        */
        if (SCAN_MODULE_NEED_RESPONSE == need_response) {
            if (scan_module->response_packet_cb) {
                unsigned idx = 0;
                while(1) {
                    struct PacketBuffer *response = stack_get_packetbuffer(stack);
                    size_t rsp_len = 0;
                    if (response == NULL) {
                        static int is_warning_printed = 0;
                        if (!is_warning_printed) {
                            LOG(0, "packet buffers empty (should be impossible)\n");
                            is_warning_printed = 1;
                        }
                        fflush(stdout);
                        pixie_usleep(100); /* no packet available */
                    }
                    if (response == NULL)
                        exit(0);
                    
                    need_response = scan_module->response_packet_cb(&parsed, entropy,
                        px, length, response->px, sizeof(response->px), &rsp_len, idx);
                    response->length = rsp_len;

                    stack_transmit_packetbuffer(stack, response);

                    if (need_response == SCAN_MODULE_NO_MORE_RESPONSE)
                        break;
                    
                    idx++;
                }
            }
        }

   
    }


    LOG(1, "[+] exiting receive thread                            \n");
    
    /*
     * cleanup
     */
end:
    if (!xconf->is_nodedup){
        dedup_destroy(dedup);
    }
    output_destroy(out);
    if (pcapfile)
        pcapfile_close(pcapfile);

    /*TODO: free stack packet buffers */

    /* Thread is about to exit */
    parms->done_receiving = 1;
}
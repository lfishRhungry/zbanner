#include "receive.h"

#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>

#include "xconf.h"
#include "globals.h"                            /* all the global variables in the program */
#include "xtatus.h"                             /* printf() regular status updates */
#include "cookie.h"                             /* for SYN-cookies on send */

#include "output/output.h"
#include "stub/stub-pcap.h"                     /* dynamically load libpcap library */
#include "smack/smack.h"                        /* Aho-corasick state-machine pattern-matcher */
#include "nmap-service/read-service-probes.h"

#include "massip/massip-parse.h"
#include "massip/massip-port.h"

#include "templ/templ-init.h"                   /* packet template, that we use to send */
#include "templ/templ-payloads.h"               /* UDP packet payloads */

#include "rawsock/rawsock.h"                    /* API on top of Linux, Windows, Mac OS X*/
#include "rawsock/rawsock-adapter.h"            /* Get Ethernet adapter configuration */
#include "rawsock/rawsock-pcapfile.h"           /* for saving pcap files w/ raw packets */

#include "stack/stack-ndpv6.h"                  /* IPv6 Neighbor Discovery Protocol */
#include "stack/stack-arpv4.h"                  /* Handle ARP resolution and requests */
#include "stack/stack-queue.h"

#include "pixie/pixie-timer.h"                  /* portable time functions */
#include "pixie/pixie-threads.h"                /* portable threads */
#include "pixie/pixie-backtrace.h"              /* maybe print backtrace on crash */

#include "crypto/crypto-siphash24.h"            /* hash function, for hash tables */
#include "crypto/crypto-blackrock.h"            /* the BlackRock shuffling func */
#include "crypto/crypto-lcg.h"                  /* the LCG randomization func */
#include "crypto/crypto-base64.h"               /* base64 encode/decode */

#include "util/throttle.h"                      /* rate limit */
#include "util/dedup.h"                         /* ignore duplicate responses */
#include "util/ptrace.h"                        /* for nmap --packet-trace feature */
#include "util/initadapter.h"
#include "util/readrange.h"
#include "util/listscan.h"
#include "util/logger.h"                        /* adjust with -v command-line opt */
#include "util/rte-ring.h"                      /* producer/consumer ring buffer */
#include "util/rstfilter.h"
#include "util/mas-malloc.h"
#include "util/checksum.h"

#include "timeout/fast-timeout.h"


/**
 * I try to implement a wrapper func for set packet in sending buffer.
 * (Damn C...)
*/
// struct StackInTransmit {
//     struct stack_t *stack;
// };

// static void
// stack_in_transmit(
//     void *SIT, unsigned char *packet, size_t length)
// {
//     struct StackInTransmit *sit = (struct StackInTransmit *)SIT;

//     struct PacketBuffer *pkt_buffer = stack_get_packetbuffer(sit->stack);
//     if (pkt_buffer == NULL) {
//         LOG(0, "packet buffers empty (should be impossible)\n");
//         fflush(stdout);
//         exit(0);
//     }

//     stack_transmit_packetbuffer(sit->stack, pkt_buffer);
// }

void
receive_thread(void *v)
{
    struct RxThread             *parms           = (struct RxThread *)v;
    const struct Xconf          *xconf           = parms->xconf;
    struct Output                output          = xconf->output;
    struct Adapter              *adapter         = xconf->nic.adapter;
    int                          data_link       = stack_if_datalink(adapter);
    struct DedupTable           *dedup           = NULL;
    struct PcapFile             *pcapfile        = NULL;
    uint64_t                     entropy         = xconf->seed;
    struct stack_t              *stack           = xconf->stack;
    struct ScanTimeoutEvent     *tm_event        = NULL;
    struct FHandler              ft_handler;

    
    
    /* For reducing RST responses, see rstfilter_is_filter() below */
    // struct ResetFilter *rf;
    // rf = rstfilter_create(entropy, 16384);

    /* some status variables */
    uint64_t *status_successed_count = MALLOC(sizeof(uint64_t));
    *status_successed_count = 0;
    parms->total_successed = status_successed_count;

    LOG(1, "[+] starting receive thread\n");

    output_init(&output);
    
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
     * Create deduplication table. This is so when somebody sends us
     * multiple responses, we only record the first one.
     */
    if (!xconf->is_nodedup)
        dedup = dedup_create(xconf->dedup_win);

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
    
    if (xconf->is_fast_timeout) {
        ft_init_handler(xconf->ft_table, &ft_handler);
    }

    /*
     * Receive packets. This is where we catch any responses and print
     * them to the terminal.
     */
    LOG(2, "[+] THREAD: recv: starting main loop\n");
    while (!is_rx_done) {

        struct ScanModule *scan_module = xconf->scan_module;

        /*handle fast-timeout event*/
        if (xconf->is_fast_timeout) {

            tm_event = ft_pop_event(&ft_handler, global_now);
            while (tm_event) {

                /*dedup timeout event and other packets together*/
                if (!xconf->is_nodedup) {
                    if (dedup_is_duplicate(dedup,
                        tm_event->ip_them, tm_event->port_them,
                        tm_event->ip_me,   tm_event->port_me,
                        tm_event->dedup_type)) {
                        free(tm_event);
                        tm_event = NULL;
                        continue;
                    }
                }

                struct OutputItem item = {
                    .ip_them   = tm_event->ip_them,
                    .ip_me     = tm_event->ip_me,
                    .port_them = tm_event->port_them,
                    .port_me   = tm_event->port_me,
                };

                scan_module->timeout_cb(entropy, tm_event, &item, stack, &ft_handler);

                output_result(&output, &item);

                free(tm_event);
                tm_event = ft_pop_event(&ft_handler, global_now);
            }
        }

        struct Received recved = {0};

        int err = rawsock_recv_packet(adapter, &(recved.length),
            &(recved.secs), &(recved.usecs), &(recved.packet));
        if (err != 0) {
            continue;
        }
        if (recved.length > 1514)
            continue;

        /*
         * "Preprocess" the response packet. This means to go through and
         * figure out where the TCP/IP headers are and the locations of
         * some fields, like IP address and port numbers.
         */
        unsigned x = preprocess_frame(recved.packet, recved.length,
            data_link, &recved.parsed);
        if (!x)
            continue; /* corrupt packet */
        
        ipaddress ip_them   = recved.parsed.src_ip;
        ipaddress ip_me     = recved.parsed.dst_ip;
        unsigned  port_them = recved.parsed.port_src;
        unsigned  port_me   = recved.parsed.port_dst;
        
        assert(ip_me.version != 0);
        assert(ip_them.version != 0);

        recved.is_myip = is_my_ip(stack->src, ip_me);
        recved.is_myport = is_my_port(stack->src, port_me);

        struct PreHandle pre = {
            .go_record = 0,
            .go_dedup = 0,
            .dedup_ip_them = ip_them,
            .dedup_port_them = port_them,
            .dedup_ip_me = ip_me,
            .dedup_port_me = port_me,
            .dedup_type = SCAN_MODULE_DEFAULT_DEDUP_TYPE,
        };

        scan_module->validate_cb(entropy, &recved, &pre);

        if (!pre.go_record)
            continue;

        if (parms->xconf->nmap.packet_trace)
            packet_trace(stdout, parms->pt_start,
                recved.packet, recved.length, 0);

        /* Save raw packet in --pcap file */
        if (pcapfile) {
            pcapfile_writeframe(pcapfile,
                recved.packet, recved.length,
                recved.length,
                recved.secs, recved.usecs);
        }

        if (!pre.go_dedup)
            continue;

        if (!xconf->is_nodedup && !pre.no_dedup) {
            if (dedup_is_duplicate(dedup,
                pre.dedup_ip_them, pre.dedup_port_them,
                pre.dedup_ip_me, pre.dedup_port_me,
                pre.dedup_type)) {
                continue;
            }
        }

        struct OutputItem item = {
            .ip_them   = ip_them,
            .ip_me     = ip_me,
            .port_them = port_them,
            .port_me   = port_me,
        };

        if (xconf->is_fast_timeout)
            scan_module->handle_cb(entropy, &recved, &item, stack, &ft_handler);
        else
            scan_module->handle_cb(entropy, &recved, &item, stack, NULL);

        output_result(&output, &item);
        
        if (item.is_success)
            (*status_successed_count)++;

    }


    LOG(1, "[+] exiting receive thread                            \n");
    
    /*
     * cleanup
     */
end:
    output_close(&output);

    if (!xconf->is_nodedup)
        dedup_destroy(dedup);
    if (pcapfile)
        pcapfile_close(pcapfile);
    if (xconf->is_fast_timeout)
        ft_close_handler(&ft_handler);

    /*TODO: free stack packet buffers */

    /* Thread is about to exit */
    parms->done_receiving = 1;
}
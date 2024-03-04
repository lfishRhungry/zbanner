#include "transmit.h"

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


void
transmit_thread(void *v) /*aka. scanning_thread() */
{
    struct TxThread            *parms          = (struct TxThread *)v;
    const struct Xconf         *xconf          = parms->xconf;
    uint64_t                    rate           = (uint64_t)xconf->max_rate;
    uint64_t                    count_ipv4     = rangelist_count(&xconf->targets.ipv4);
    uint64_t                    count_ipv6     = range6list_count(&xconf->targets.ipv6).lo;
    struct Throttler           *throttler      = parms->throttler;
    struct Adapter             *adapter        = xconf->nic.adapter;
    uint64_t                    packets_sent   = 0;
    unsigned                    increment      = xconf->shard.of * xconf->tx_thread_count;
    uint64_t                    seed           = xconf->seed;
    uint64_t                    repeats        = 0; /* --infinite repeats */
    uint64_t                    entropy        = xconf->seed;
    struct ScanTimeoutEvent    *tm_event       =  NULL;
    struct FHandler             ft_handler;
    // struct TemplateSet tmplset = templ_copy(xconf->tmplset);

    /* Wait to make sure receive_thread is ready */
    pixie_usleep(1000000);
    LOG(1, "[+] starting transmit thread #%u\n", parms->tx_index);
    
    /* Lock threads to the CPUs one by one.
     * Tx threads follow  the only one Rx thread.
     * TODO: Make CPU locking be settable. 
     */
    if (pixie_cpu_get_count() > 1) {
        unsigned cpu_count = pixie_cpu_get_count();
        unsigned cpu = (parms->tx_index+1)%cpu_count;
        /* I think it is better to make (cpu>=cpu_count) threads free */
        if (cpu<cpu_count)
            pixie_cpu_set_affinity(cpu);
    }

    /* export a pointer to this variable outside this threads so
     * that the 'status' system can print the rate of syns we are
     * sending */
    uint64_t *status_sent_count = MALLOC(sizeof(uint64_t));
    *status_sent_count = 0;
    parms->total_sent = status_sent_count;

    /* Normally, we have just one source address. In special cases, though
     * we can have multiple. */
    struct source_t src;
    adapter_get_source_addresses(xconf, &src);

    if (xconf->is_fast_timeout) {
        ft_init_handler(xconf->ft_table, &ft_handler);
    }


    /* "THROTTLER" rate-limits how fast we transmit, set with the
     * --max-rate parameter */
    throttler_start(throttler, xconf->max_rate/xconf->tx_thread_count);

infinite:
    
    /* Create the shuffler/randomizer. This creates the 'range' variable,
     * which is simply the number of IP addresses times the number of
     * ports.
     * IPv6: low index will pick addresses from the IPv6 ranges, and high
     * indexes will pick addresses from the IPv4 ranges. */
    uint64_t range = count_ipv4 * rangelist_count(&xconf->targets.ports)
            + count_ipv6 * rangelist_count(&xconf->targets.ports);
    uint64_t range_ipv6 = count_ipv6 * rangelist_count(&xconf->targets.ports);

    struct BlackRock blackrock;
    blackrock_init(&blackrock, range, seed, xconf->blackrock_rounds);

    /* Calculate the 'start' and 'end' of a scan. One reason to do this is
     * to support --shard, so that multiple machines can co-operate on
     * the same scan. Another reason to do this is so that we can bleed
     * a little bit past the end when we have --retries. Yet another
     * thing to do here is deal with multiple network adapters, which
     * is essentially the same logic as shards. */
    uint64_t start = xconf->resume.index
        + (xconf->shard.one-1) * xconf->tx_thread_count
        + parms->tx_index;
    uint64_t end = range;
    if (xconf->resume.count && end > start + xconf->resume.count)
        end = start + xconf->resume.count;


    /* -----------------
     * the main loop
     * -----------------*/
    LOG(3, "THREAD: xmit: starting main loop: [%llu..%llu]\n", start, end);

    uint64_t i;
    unsigned more_idx = 0;
    for (i=start; i<end; ) {

        /*
         * Do a batch of many packets at a time. That because per-packet
         * throttling is expensive at 10-million pps, so we reduce the
         * per-packet cost by doing batches. At slower rates, the batch
         * size will always be one. (--max-rate)
         */
        uint64_t batch_size = throttler_next_batch(throttler, packets_sent);

        /*
         * Transmit packets from other thread, when doing --banners. This
         * takes priority over sending SYN packets. If there is so much
         * activity grabbing banners that we cannot transmit more SYN packets,
         * then "batch_size" will get decremented to zero, and we won't be
         * able to transmit SYN packets.
         */
        stack_flush_packets(xconf->stack, adapter, &packets_sent, &batch_size);


        /*
         * Transmit a bunch of packets. At any rate slower than 100,000
         * packets/second, the 'batch_size' is likely to be 1. At higher
         * rates, we can't afford to throttle on a per-packet basis and 
         * instead throttle on a per-batch basis. In other words, throttle
         * based on 2-at-a-time, 3-at-time, and so on, with the batch
         * size increasing as the packet rate increases. This gives us
         * very precise packet-timing for low rates below 100,000 pps,
         * while not incurring the overhead for high packet rates.
         */

        while (batch_size && i < end) {
            /*
             * RANDOMIZE THE TARGET:
             *  This is kinda a tricky bit that picks a random IP and port
             *  number in order to scan. We monotonically increment the
             *  index 'i' from [0..range]. We then shuffle (randomly transmog)
             *  that index into some other, but unique/1-to-1, number in the
             *  same range. That way we visit all targets, but in a random
             *  order. Then, once we've shuffled the index, we "pick" the
             *  IP address and port that the index refers to.
             */
            uint64_t xXx = i;
            if (rate > range) {
                xXx %= range;
            } else {
                while (xXx >= range) {
                    xXx -= range;
                }
            }
            xXx = blackrock_shuffle(&blackrock,  xXx);

            /**
             * figure out src/dst
            */

            struct ScanTarget target = {.index = more_idx};
            
            if (xXx < range_ipv6) {
                /* Our index selects an IPv6 target */
                target.ip_them.version = 6;
                target.ip_me.version   = 6;
                target.ip_them.ipv6    = range6list_pick(&xconf->targets.ipv6, xXx % count_ipv6);
                target.port_them       = rangelist_pick(&xconf->targets.ports, xXx / count_ipv6);
                target.ip_me.ipv6      = src.ipv6;

            } else {
                /* Our index selects an IPv4 target. In other words, low numbers
                 * index into the IPv6 ranges, and high numbers index into the
                 * IPv4 ranges. */
                target.ip_them.version = 4;
                target.ip_me.version   = 4;

                xXx -= range_ipv6;

                target.ip_them.ipv4 = rangelist_pick(&xconf->targets.ipv4, xXx % count_ipv4);
                target.port_them    = rangelist_pick(&xconf->targets.ports, xXx / count_ipv4);
                target.ip_me.ipv4   = src.ipv4;

            }

            if (src.port_mask > 1) {
                uint64_t ck = get_cookie_ipv4((unsigned)(i+repeats),
                                        (unsigned)((i+repeats)>>32),
                                        (unsigned)xXx, (unsigned)(xXx>>32),
                                        entropy);
                target.port_me = src.port + (ck & src.port_mask);
            } else {
                target.port_me = src.port;
            }

            /**
             * Due to our port store method.
             * I think it is flexible.
            */
            target.proto = get_real_protocol_and_port(&(target.port_them));

            /*if we don't use fast-timeout, don't malloc more memory*/
            if (!tm_event) {
                tm_event = CALLOC(1, sizeof(struct ScanTimeoutEvent));
            }

            tm_event->ip_them   = target.ip_them;
            tm_event->ip_me     = target.ip_me;
            tm_event->port_them = target.port_them;
            tm_event->port_me   = target.port_me;

            unsigned char pkt_buffer[PKT_BUF_LEN];
            size_t pkt_len = 0;

            int more = 0;
            more = xconf->scan_module->transmit_cb(
                entropy, &target, tm_event, pkt_buffer, &pkt_len);

            if (pkt_len) {
                /* send packets (bypassing the kernal)*/
                rawsock_send_packet(adapter, pkt_buffer, (unsigned)pkt_len, !batch_size);
                batch_size--;
                packets_sent++;
                status_sent_count++;

                /*add timeout event*/
                if (xconf->is_fast_timeout && tm_event->need_timeout) {
                    ft_add_event(&ft_handler, tm_event);
                    tm_event = NULL;
                } else {
                    tm_event->need_timeout = 0;
                }
            }

            if (more) {
                more_idx++;
            } else {
                i += increment; /* <------ increment by 1 normally, more with shards/nics */
                more_idx = 0;
            }

        } /* end of batch */


        /* save our current location for resuming, if the user pressed
         * <ctrl-c> to exit early */
        parms->my_index = i;

        /* If the user pressed <ctrl-c>, then we need to exit. In case
         * the user wants to --resume the scan later, we save the current
         * state in a file */
        if (is_tx_done) {
            break;
        }
    }

    /*
     * --infinite
     *  For load testing, go around and do this again
     */
    if (xconf->is_infinite && !is_tx_done) {
        seed++;
        repeats++;
        goto infinite;
    }

    /*
     * Flush any untransmitted packets. High-speed mechanisms like Windows
     * "sendq" and Linux's "PF_RING" queue packets and transmit many together,
     * so there may be some packets that we've queued but not yet transmitted.
     * This call makes sure they are transmitted.
     */
    rawsock_flush(adapter);

    /*
     * Wait until the receive thread realizes the scan is over
     */
    LOG(1, "[+] transmit thread #%u complete\n", parms->tx_index);

    /*
     * We are done transmitting. However, response packets will take several
     * seconds to arrive. Therefore, sit in short loop waiting for those
     * packets to arrive. Pressing <ctrl-c> a second time will exit this
     * prematurely.
     */
    while (!is_rx_done) {
        unsigned k;
        uint64_t batch_size;

        for (k=0; k<1000; k++) {
            
            /*
             * Only send a few packets at a time, throttled according to the max
             * --max-rate set by the user
             */
            batch_size = throttler_next_batch(throttler, packets_sent);


            /* Transmit packets from the receive thread */
            stack_flush_packets(xconf->stack, adapter, &packets_sent, &batch_size);

            /* Make sure they've actually been transmitted, not just queued up for
             * transmit */
            rawsock_flush(adapter);

            pixie_usleep(100);
        }
    }

    /*clean up*/
    if (xconf->is_fast_timeout)
        ft_close_handler(&ft_handler);

    /* Thread is about to exit */
    parms->done_transmitting = 1;
    LOG(1, "[+] exiting transmit thread #%u                    \n", parms->tx_index);
}
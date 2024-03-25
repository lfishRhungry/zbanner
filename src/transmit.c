#include "transmit.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cookie.h"
#include "globals.h"
#include "xconf.h"

#include "massip/massip-parse.h"

#include "templ/templ-init.h"

#include "rawsock/rawsock-adapter.h"
#include "rawsock/rawsock.h"

#include "stack/stack-arpv4.h"

#include "pixie/pixie-threads.h"
#include "pixie/pixie-timer.h"

#include "crypto/crypto-blackrock.h"

#include "util/logger.h"
#include "util/fine-malloc.h"
#include "util/readrange.h"
#include "util/throttle.h"

void transmit_thread(void *v)
{
    struct TxThread *parms            = (struct TxThread *)v;
    const struct Xconf *xconf         = parms->xconf;
    uint64_t rate                     = (uint64_t)xconf->max_rate;
    uint64_t count_ipv4               = rangelist_count(&xconf->targets.ipv4);
    uint64_t count_ipv6               = range6list_count(&xconf->targets.ipv6).lo;
    struct Throttler *throttler       = parms->throttler;
    struct Adapter *adapter           = xconf->nic.adapter;
    uint64_t packets_sent             = 0;
    unsigned increment                = xconf->shard.of * xconf->tx_thread_count;
    uint64_t seed                     = xconf->seed;
    uint64_t repeats                  = 0; /* --infinite repeats */
    uint64_t entropy                  = xconf->seed;
    struct ScanTimeoutEvent *tm_event = NULL;
    struct FHandler ft_handler;

    /* Wait to make sure receive_thread is ready */
    pixie_usleep(1000000);
    LOG(LEVEL_WARNING, "[+] starting transmit thread #%u\n", parms->tx_index);

    /* Lock threads to the CPUs one by one.
     * Tx threads follow  the only one Rx thread.
     * TODO: Make CPU locking be settable.
     */
    if (pixie_cpu_get_count() > 1) {
        unsigned cpu_count = pixie_cpu_get_count();
        unsigned cpu       = (parms->tx_index + 1) % cpu_count;
        /* I think it is better to make (cpu>=cpu_count) threads free */
        if (cpu < cpu_count)
            pixie_cpu_set_affinity(cpu);
    }

    uint64_t *status_sent_count;
    status_sent_count  = MALLOC(sizeof(uint64_t));
    *status_sent_count = 0;
    parms->total_sent  = status_sent_count;

    /* Normally, we have just one source address. In special cases, though
     * we can have multiple. */
    struct source_t src;
    adapter_get_source_addresses(xconf, &src);

    if (xconf->is_fast_timeout) {
        ft_init_handler(xconf->ft_table, &ft_handler);
    }

    throttler_start(throttler, xconf->max_rate / xconf->tx_thread_count);

infinite:

    /* Create the shuffler/randomizer. This creates the 'range' variable,
     * which is simply the number of IP addresses times the number of
     * ports.
     * IPv6: low index will pick addresses from the IPv6 ranges, and high
     * indexes will pick addresses from the IPv4 ranges. */
    uint64_t range = count_ipv4 * rangelist_count(&xconf->targets.ports) +
                     count_ipv6 * rangelist_count(&xconf->targets.ports);
    uint64_t range_ipv6 = count_ipv6 * rangelist_count(&xconf->targets.ports);

    struct BlackRock blackrock;
    blackrock_init(&blackrock, range, seed, xconf->blackrock_rounds);

    /* Calculate the 'start' and 'end' of a scan. One reason to do this is
     * to support --shard, so that multiple machines can co-operate on
     * the same scan. */
    uint64_t start = xconf->resume.index +
                     (xconf->shard.one - 1) * xconf->tx_thread_count +
                     parms->tx_index;
    uint64_t end = range;
    if (xconf->resume.count && end > start + xconf->resume.count)
        end = start + xconf->resume.count;

    LOG(LEVEL_DEBUG, "THREAD: xmit: starting main loop: [%llu..%llu]\n", start, end);

    uint64_t i;
    unsigned more_idx = 0;
    for (i = start; i < end;) {

        uint64_t batch_size = throttler_next_batch(throttler, packets_sent);

        /*Transmit packets from stack first */
        stack_flush_packets(xconf->stack, adapter, &packets_sent, &batch_size);

        while (batch_size && i < end) {
            uint64_t xXx = i;
            if (rate > range) {
                xXx %= range;
            } else {
                while (xXx >= range) {
                    xXx -= range;
                }
            }
            xXx = blackrock_shuffle(&blackrock, xXx);

            /*
             * figure out src/dst
             */

            struct ScanTarget target = {.index = more_idx};

            if (xXx < range_ipv6) {
                target.ip_them.version = 6;
                target.ip_me.version = 6;
                target.ip_them.ipv6 =
                    range6list_pick(&xconf->targets.ipv6, xXx % count_ipv6);
                target.port_them =
                    rangelist_pick(&xconf->targets.ports, xXx / count_ipv6);
                target.ip_me.ipv6 = src.ipv6;
            } else {
                xXx -= range_ipv6;

                target.ip_them.version = 4;
                target.ip_me.version = 4;
                target.ip_them.ipv4 =
                    rangelist_pick(&xconf->targets.ipv4, xXx % count_ipv4);
                target.port_them =
                    rangelist_pick(&xconf->targets.ports, xXx / count_ipv4);
                target.ip_me.ipv4 = src.ipv4;
            }

            if (src.port_mask > 1) {
                uint64_t ck = get_cookie_ipv4(
                    (unsigned)(i + repeats), (unsigned)((i + repeats) >> 32),
                    (unsigned)xXx, (unsigned)(xXx >> 32), entropy);
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
            more = xconf->scan_module->transmit_cb(entropy, &target, tm_event,
                                                   pkt_buffer, &pkt_len);

            if (pkt_len) {
                /* send packets (bypassing the kernal)*/
                rawsock_send_packet(adapter, pkt_buffer, (unsigned)pkt_len,
                                    !batch_size);
                batch_size--;
                packets_sent++;
                status_sent_count++;

                /*add timeout event*/
                if (xconf->is_fast_timeout && tm_event->need_timeout) {
                    ft_add_event(&ft_handler, tm_event, global_now);
                    tm_event = NULL;
                } else {
                    tm_event->need_timeout = 0;
                    tm_event->dedup_type   = 0;
                }
            }

            if (more) {
                more_idx++;
            } else {
                i += increment;
                more_idx = 0;
            }

        } /* end of batch */

        /* save our current location for resuming, if the user pressed
         * <ctrl-c> to exit early */
        parms->my_index = i;

        /* If the user pressed <ctrl-c>, then we need to exit and save state.*/
        if (is_tx_done) {
            break;
        }
    }

    /*
     * --infinite
     */
    if (xconf->is_infinite && !is_tx_done) {
        seed++;
        repeats++;
        goto infinite;
    }

    /*
     * Makes sure all packets are transmitted while in sendq or PF_RING mode.
     */
    rawsock_flush(adapter);

    /*
     * Wait until the receive thread realizes the scan is over
     */
    LOG(LEVEL_WARNING, "[+] transmit thread #%u complete\n", parms->tx_index);

    /*help rx thread to reponse*/
    while (!is_rx_done) {
        unsigned k;
        uint64_t batch_size;

        for (k = 0; k < 1000; k++) {
            batch_size = throttler_next_batch(throttler, packets_sent);
            stack_flush_packets(xconf->stack, adapter, &packets_sent, &batch_size);
            rawsock_flush(adapter);
            pixie_usleep(100);
        }
    }

    if (xconf->is_fast_timeout)
        ft_close_handler(&ft_handler);

    parms->done_transmitting = 1;
    LOG(LEVEL_WARNING, "[+] exiting transmit thread #%u                    \n",
        parms->tx_index);
}

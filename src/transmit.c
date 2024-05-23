#include "transmit.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "massip/massip-cookie.h"
#include "globals.h"
#include "xconf.h"
#include "version.h"

#include "massip/massip-parse.h"
#include "massip/massip-rangesport.h"

#include "templ/templ-init.h"

#include "rawsock/rawsock-adapter.h"
#include "rawsock/rawsock.h"

#include "stack/stack-arpv4.h"

#include "pixie/pixie-threads.h"
#include "pixie/pixie-timer.h"

#include "crypto/crypto-blackrock.h"

#include "util-out/logger.h"
#include "util-data/fine-malloc.h"
#include "util-scan/readrange.h"
#include "util-scan/throttle.h"

static void
adapter_get_source_addresses(const struct Xconf *xconf, struct source_t *src)
{
    const struct stack_src_t *ifsrc = &xconf->nic.src;
    static ipv6address mask = {~0ULL, ~0ULL};

    src->ipv4 = ifsrc->ipv4.first;
    src->ipv4_mask = ifsrc->ipv4.last - ifsrc->ipv4.first;

    src->port = ifsrc->port.first;
    src->port_mask = ifsrc->port.last - ifsrc->port.first;

    src->ipv6 = ifsrc->ipv6.first;

    /* TODO: currently supports only a single address */
    src->ipv6_mask = mask;
}

void transmit_thread(void *v)
{
    struct TxThread             *parms                    = (struct TxThread *)v;
    const struct Xconf          *xconf                    = parms->xconf;
    uint64_t                     rate                     = (uint64_t)xconf->max_rate;
    uint64_t                     count_ipv4               = rangelist_count(&xconf->targets.ipv4);
    uint64_t                     count_ipv6               = range6list_count(&xconf->targets.ipv6).lo;
    struct Throttler            *throttler                = parms->throttler;
    struct Adapter              *adapter                  = xconf->nic.adapter;
    uint64_t                     packets_sent             = 0;
    unsigned                     increment                = xconf->shard.of * xconf->tx_thread_count;
    uint64_t                     dynamic_seed             = xconf->seed;
    uint64_t                     entropy                  = xconf->seed;
    struct ScanTmEvent          *tm_event                 = NULL;
    struct FHandler             *ft_handler               = NULL;
    uint64_t                    *status_sent_count;

    /* Wait to make sure receive_thread is ready */
    pixie_usleep(1000000);
    LOG(LEVEL_WARNING, "[+] starting transmit thread #%u\n", parms->tx_index);

    char th_name[30];
    snprintf(th_name, sizeof(th_name), XTATE_NAME" transmit #%u", parms->tx_index);
    pixie_set_thread_name(th_name);

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

    status_sent_count      = MALLOC(sizeof(uint64_t));
    *status_sent_count     = 0;
    parms->total_sent      = status_sent_count;

    /* Normally, we have just one source address. In special cases, though
     * we can have multiple. */
    struct source_t src;
    adapter_get_source_addresses(xconf, &src);

    if (xconf->is_fast_timeout) {
        ft_handler = ft_get_handler(xconf->ft_table);
    }

    throttler_start(throttler, xconf->max_rate / xconf->tx_thread_count);

infinite:;

    uint64_t range      = count_ipv4 * rangelist_count(&xconf->targets.ports) +
                          count_ipv6 * rangelist_count(&xconf->targets.ports);
    uint64_t range_ipv6 = count_ipv6 * rangelist_count(&xconf->targets.ports);

    struct BlackRock blackrock;
    blackrock_init(&blackrock, range, dynamic_seed, xconf->blackrock_rounds);

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
                    (unsigned)(i + parms->my_repeat),
                    (unsigned)((i + parms->my_repeat) >> 32),
                    (unsigned)xXx, (unsigned)(xXx >> 32), dynamic_seed);
                target.port_me = src.port + (ck & src.port_mask);
            } else {
                target.port_me = src.port;
            }

            /**
             * Due to flexible port store method.
             */
            target.ip_proto = get_actual_proto_port(&(target.port_them));

            /*if we don't use fast-timeout, do not malloc more memory*/
            if (!tm_event) {
                tm_event = CALLOC(1, sizeof(struct ScanTmEvent));
            }

            tm_event->ip_proto  = target.ip_proto;
            tm_event->ip_them   = target.ip_them;
            tm_event->ip_me     = target.ip_me;
            tm_event->port_them = target.port_them;
            tm_event->port_me   = target.port_me;

            unsigned char pkt_buffer[PKT_BUF_LEN];
            size_t pkt_len = 0;

            unsigned more = 0;
            more = xconf->scan_module->transmit_cb(
                entropy, &target, tm_event, pkt_buffer, &pkt_len);

            /*
             * send packet actually
             */
            if (pkt_len) {
                rawsock_send_packet(
                    adapter, pkt_buffer, (unsigned)pkt_len, !batch_size);

                batch_size--;
                packets_sent++;
                status_sent_count++;

                /*add timeout event*/
                if (xconf->is_fast_timeout && tm_event->need_timeout) {
                    ft_add_event(ft_handler, tm_event, global_now);
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

        /* save our current location for resuming */
        parms->my_index = i;

        /* If the user pressed <ctrl-c>, then we need to exit and save state.*/
        if (time_to_finish_tx) {
            break;
        }
    }

    /*
     * --infinite, --repeat, --static-seed
     * Set repeat as condition to avoid more packets sending.
     */
    if (xconf->is_infinite && !time_to_finish_tx) {
        if ((xconf->repeat && parms->my_repeat<xconf->repeat)
            || !xconf->repeat) {
            /* update dynamic_seed and my_repeat while going again*/
            if (!xconf->is_static_seed) {
                dynamic_seed++;
            }
            parms->my_repeat++;
            goto infinite;
        }
    }

    /*
     * Makes sure all packets are transmitted while in sendq or PF_RING mode.
     */
    rawsock_flush(adapter);

    LOG(LEVEL_WARNING, "[+] transmit thread #%u complete\n", parms->tx_index);

    /*help rx thread to reponse*/
    uint64_t batch_size;
    while (!time_to_finish_rx) {
        batch_size = throttler_next_batch(throttler, packets_sent);
        stack_flush_packets(xconf->stack, adapter, &packets_sent, &batch_size);
        rawsock_flush(adapter);
    }

    if (xconf->is_fast_timeout)
        ft_close_handler(ft_handler);

    parms->done_transmitting = true;
    LOG(LEVEL_WARNING, "[+] exiting transmit thread #%u                    \n",
        parms->tx_index);
}

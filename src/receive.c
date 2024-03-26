#include "receive.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "globals.h"
#include "xconf.h"
#include "cookie.h"

#include "output/output.h"

#include "rawsock/rawsock-adapter.h"
#include "rawsock/rawsock-pcapfile.h"
#include "rawsock/rawsock.h"

#include "stack/stack-arpv4.h"
#include "stack/stack-ndpv6.h"
#include "stack/stack-queue.h"

#include "pixie/pixie-threads.h"
#include "pixie/pixie-timer.h"

#include "util/dedup.h"
#include "util/logger.h"
#include "util/fine-malloc.h"
#include "util/ptrace.h"
#include "util/readrange.h"

#include "timeout/fast-timeout.h"

#define RECV_QUEUE_COUNT 65536

struct RxDispatch {
    uint64_t entropy;
    struct rte_ring  *dispatch_queue;
    struct rte_ring **handle_queue;
    unsigned recv_handle_num;
    unsigned recv_handle_mask;
};

static void
dispatch_thread(void *v)
{
    struct RxDispatch *parms = v;
    while (!is_rx_done) {
        int err = 1;
        struct Received *recved = NULL;

        err = rte_ring_sc_dequeue(parms->dispatch_queue, (void**)&recved);
        if (err != 0) {
            pixie_usleep(100);
            continue;
        }

        if (recved==NULL) {
            LOG(LEVEL_ERROR, "FAIL: recv empty from dispatch thread. (IMPOSSIBLE)\n");
            fflush(stdout);
            exit(1);
        }

        /**
         * send packet to recv handle queue by its cookie
        */

        uint64_t cookie = get_cookie(recved->parsed.src_ip, recved->parsed.port_src,
            recved->parsed.dst_ip, recved->parsed.port_dst, parms->entropy);

        for (err=1; err; ) {
            unsigned i = cookie & parms->recv_handle_mask;
            err = rte_ring_sp_enqueue(
                parms->handle_queue[i], recved);
            if (err) {
                fprintf(stderr, "[-] handle queue #%d full from dispatch thread.\n", i);
                pixie_usleep(1000);
            }
        }
    }
}

struct RxHandle {
    struct ScanModule *scan_module;
    struct rte_ring *handle_queue;
    struct FHandler *ft_handler;
    struct stack_t  *stack;
    struct Output   *out;

    uint64_t entropy;
    unsigned index;
};

static void
handle_thread(void *v)
{
    struct RxHandle *parms = v;
    while (!is_rx_done) {
        int err = 1;

        struct Received *recved = NULL;

        err = rte_ring_sc_dequeue(parms->handle_queue, (void**)&recved);
        if (err != 0) {
            pixie_usleep(100);
            continue;
        }

        if (recved==NULL) {
            LOG(LEVEL_ERROR, "FAIL: recv empty from handle thread. (IMPOSSIBLE)\n");
            fflush(stdout);
            exit(1);
        }

        struct OutputItem item = {
            .ip_them   = recved->parsed.src_ip,
            .ip_me     = recved->parsed.dst_ip,
            .port_them = recved->parsed.port_src,
            .port_me   = recved->parsed.port_dst,
        };

        parms->scan_module->handle_cb(parms->entropy, recved, &item,
            parms->stack, parms->ft_handler);

        output_result(parms->out, &item);

        free(recved->packet);
        free(recved);
    }
}


void receive_thread(void *v) {
    struct RxThread               *parms                       = (struct RxThread *)v;
    const struct Xconf            *xconf                       = parms->xconf;
    struct Output                 *output                      = (struct Output *)(&xconf->output);
    struct Adapter                *adapter                     = xconf->nic.adapter;
    int                            data_link                   = stack_if_datalink(adapter);
    struct DedupTable             *dedup                       = NULL;
    struct PcapFile               *pcapfile                    = NULL;
    uint64_t                       entropy                     = xconf->seed;
    struct stack_t                *stack                       = xconf->stack;
    struct ScanTimeoutEvent       *tm_event                    = NULL;
    unsigned                       handler_num                 = xconf->rx_handler_count;
    struct RxHandle                handle_parms[handler_num];
    size_t                         handler[handler_num];
    struct rte_ring               *handle_q[handler_num];
    struct RxDispatch              dispatch_parms;
    size_t                         dispatcher;
    struct rte_ring               *dispatch_q;
    struct FHandler                ft_handler;

    /* some status variables */
    uint64_t *status_successed_count = MALLOC(sizeof(uint64_t));
    uint64_t *status_failed_count    = MALLOC(sizeof(uint64_t));
    uint64_t *status_timeout_count   = MALLOC(sizeof(uint64_t));
    *status_successed_count          = 0;
    *status_failed_count             = 0;
    *status_timeout_count            = 0;
    parms->total_successed           = status_successed_count;
    parms->total_failed              = status_failed_count;
    parms->total_tm_event            = status_timeout_count;
    output->total_successed          = status_successed_count; /*update in output*/
    output->total_failed             = status_failed_count;    /*update in output*/

    LOG(LEVEL_WARNING, "[+] starting receive thread\n");

    if (xconf->is_offline) {
        while (!is_rx_done)
            pixie_usleep(10000);
        parms->done_receiving = 1;
        return;
    }

    output_init(output);

    /* Lock threads to the CPUs one by one.
     * Tx threads follow  the only one Rx thread.
     */
    if (pixie_cpu_get_count() > 1) {
        pixie_cpu_set_affinity(0);
    }

    if (xconf->pcap_filename[0]) {
        pcapfile = pcapfile_openwrite(xconf->pcap_filename, 1);
    }

    if (!xconf->is_nodedup)
        dedup = dedup_create(xconf->dedup_win);

    if (xconf->is_fast_timeout) {
        ft_init_handler(xconf->ft_table, &ft_handler);
    }

    /**
     * init dispatch and handle threads
    */
    dispatch_q = rte_ring_create(RECV_QUEUE_COUNT,
        RING_F_SP_ENQ|RING_F_SC_DEQ);
    for (unsigned i=0; i<handler_num; i++) {
        handle_q[i] = rte_ring_create(RECV_QUEUE_COUNT,
            RING_F_SP_ENQ|RING_F_SC_DEQ);
    }

    dispatch_parms.entropy = entropy;
    dispatch_parms.dispatch_queue = dispatch_q;
    dispatch_parms.handle_queue = handle_q;
    dispatch_parms.recv_handle_num = handler_num;
    dispatch_parms.recv_handle_mask = handler_num-1;

    dispatcher = pixie_begin_thread(dispatch_thread, 0, &dispatch_parms);


    for (unsigned i=0; i<handler_num; i++) {
        handle_parms[i].scan_module = xconf->scan_module;
        handle_parms[i].handle_queue = handle_q[i];
        handle_parms[i].ft_handler = xconf->is_fast_timeout?&ft_handler:NULL;
        handle_parms[i].stack = stack;
        handle_parms[i].out = output;
        handle_parms[i].entropy = entropy;
        handle_parms[i].index = i;

        handler[i] = pixie_begin_thread(handle_thread, 0, &handle_parms[i]);
    }

    LOG(LEVEL_INFO, "[+] THREAD: recv: starting main loop\n");
    while (!is_rx_done) {

        struct ScanModule *scan_module = xconf->scan_module;

        /*handle a fast-timeout event in each loop*/
        if (xconf->is_fast_timeout) {

            tm_event = ft_pop_event(&ft_handler, global_now);
            /*dedup timeout event and other packets together*/
            if (tm_event) {
                if ((!xconf->is_nodedup &&
                     !dedup_is_duplicate(dedup,
                        tm_event->ip_them, tm_event->port_them,
                        tm_event->ip_me, tm_event->port_me,
                        tm_event->dedup_type))
                    || xconf->is_nodedup) {

                    struct OutputItem item = {
                        .ip_them   = tm_event->ip_them,
                        .ip_me     = tm_event->ip_me,
                        .port_them = tm_event->port_them,
                        .port_me   = tm_event->port_me,
                    };

                    scan_module->timeout_cb(entropy, tm_event, &item,
                        stack, &ft_handler);

                    output_result(output, &item);

                }
                free(tm_event);
                tm_event = NULL;
            }

            *status_timeout_count = ft_event_count(&ft_handler);
        }

        /**
         * Do polling for scan module in each loop
        */
        scan_module->poll_cb();

        unsigned pkt_len, pkt_secs, pkt_usecs;
        const unsigned char *pkt_data;

        int err = rawsock_recv_packet(adapter, &pkt_len, &pkt_secs,
                                      &pkt_usecs, &pkt_data);
        if (err != 0) {
            continue;
        }
        if (pkt_len > 1514) {
            continue;
        }

        /**
         * recved will not be handle in this thread.
         * and packet received from Adapters cannot exist too long.
        */
        struct Received *recved = CALLOC(1, sizeof(struct Received));
        recved->packet = MALLOC(pkt_len);
        memcpy(recved->packet, pkt_data, pkt_len);
        recved->length = pkt_len;
        recved->secs = pkt_secs;
        recved->usecs = pkt_usecs;

        unsigned x = preprocess_frame(recved->packet, recved->length, data_link,
                                      &recved->parsed);
        if (!x) {
            free(recved->packet);
            free(recved);
            continue; /* corrupt packet */
        }

        ipaddress ip_them   = recved->parsed.src_ip;
        ipaddress ip_me     = recved->parsed.dst_ip;
        unsigned  port_them = recved->parsed.port_src;
        unsigned  port_me   = recved->parsed.port_dst;

        assert(ip_me.version   != 0);
        assert(ip_them.version != 0);

        recved->is_myip   = is_my_ip(stack->src, ip_me);
        recved->is_myport = is_my_port(stack->src, port_me);

        struct PreHandle pre = {
            .go_record       = 0,
            .go_dedup        = 0,
            .dedup_ip_them   = ip_them,
            .dedup_port_them = port_them,
            .dedup_ip_me     = ip_me,
            .dedup_port_me   = port_me,
            .dedup_type      = SCAN_MODULE_DEFAULT_DEDUP_TYPE,
        };

        scan_module->validate_cb(entropy, recved, &pre);

        if (!pre.go_record) {
            free(recved->packet);
            free(recved);
            continue;
        }

        if (parms->xconf->packet_trace)
            packet_trace(stdout, parms->pt_start, recved->packet, recved->length, 0);

        /* Save raw packet in --pcap file */
        if (pcapfile) {
            pcapfile_writeframe(pcapfile, recved->packet, recved->length,
                recved->length, recved->secs, recved->usecs);
        }

        if (!pre.go_dedup) {
            free(recved->packet);
            free(recved);
            continue;
        }

        if (!xconf->is_nodedup && !pre.no_dedup) {
            if (dedup_is_duplicate(dedup, pre.dedup_ip_them, pre.dedup_port_them,
                                   pre.dedup_ip_me, pre.dedup_port_me,
                                   pre.dedup_type)) {
                free(recved->packet);
                free(recved);
                continue;
            }
        }

        /**
         * give it to reader and to handlers
        */
        for (err=1; err; ) {
            err = rte_ring_sp_enqueue(dispatch_q, recved);
            if (err) {
                fprintf(stderr, "[-] dispatch queue full from rx thread with too fast rate.\n");
                pixie_usleep(1000);
                // exit(1);
            }
        }
    }

    LOG(LEVEL_WARNING, "[+] exiting receive thread                            \n");

    /*
     * cleanup
     */
    /*stop reader and handlers*/
    pixie_thread_join(dispatcher);
    for (unsigned i=0; i<handler_num; i++) {
        pixie_thread_join(handler[i]);
    }

    output_close(output);

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

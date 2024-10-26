#include "receive.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "globals.h"
#include "xconf.h"
#include "version.h"
#include "target/target-cookie.h"

#include "rawsock/rawsock.h"
#include "util-out/pcapfile.h"

#include "stack/stack-arpv4.h"
#include "stack/stack-ndpv6.h"
#include "stack/stack-queue.h"

#include "pixie/pixie-threads.h"
#include "pixie/pixie-timer.h"

#include "templ/templ-icmp.h"
#include "templ/templ-arp.h"

#include "dedup/dedup.h"
#include "util-out/logger.h"
#include "util-data/fine-malloc.h"
#include "util-scan/ptrace.h"

#include "output-modules/output-modules.h"

static uint8_t _dispatch_hash(ipaddress addr) {
    uint64_t ret = 0;

    if (addr.version == 4) {
        ret = (addr.ipv4 >> 16) ^ addr.ipv4;
        ret ^= (ret >> 8);
    } else if (addr.version == 6) {
        ret = addr.ipv6.hi ^ addr.ipv6.lo;
        ret ^= (ret >> 32);
        ret ^= (ret >> 16);
        ret ^= (ret >> 8);
    }

    return ret & 0xFF;
}

typedef struct RxDispatchConfig {
    PACKET_QUEUE **handle_queue;
    PACKET_QUEUE  *dispatch_queue;
    unsigned       recv_handle_num;
    unsigned       recv_handle_mask;
    uint64_t       entropy;
} DispatchConf;

static void dispatch_thread(void *v) {
    LOG(LEVEL_DEBUG, "starting dispatch thread\n");
    pixie_set_thread_name(XTATE_NAME "-dsp");

    DispatchConf *parms = v;
    while (!time_to_finish_rx) {
        int     err    = 1;
        Recved *recved = NULL;

        err = rte_ring_sc_dequeue(parms->dispatch_queue, (void **)&recved);
        if (err != 0) {
            pixie_usleep(RTE_XTATE_DEQ_USEC);
            continue;
        }

        if (recved == NULL) {
            LOG(LEVEL_ERROR,
                "got empty Recved in dispatch thread. (IMPOSSIBLE)\n");
            fflush(stdout);
            exit(1);
        }

        /**
         * Send packet to recv handle queue according to ip_them.
         * Ensure same target ip was dispatched to same handle thread.
         */
        uint8_t dsp_hash = _dispatch_hash(recved->parsed.src_ip);

        for (err = 1; err != 0;) {
            unsigned i = dsp_hash & parms->recv_handle_mask;
            err        = rte_ring_sp_enqueue(parms->handle_queue[i], recved);
            if (err != 0) {
                LOG(LEVEL_ERROR,
                    "handle queue #%d full from dispatch thread.\n", i);
                pixie_usleep(RTE_XTATE_ENQ_USEC);
            }
        }
    }

    LOG(LEVEL_DEBUG, "exiting dispatch thread\n");
}

typedef struct RxHandleConfig {
    /** This points to the central configuration. Note that it's 'const',
     * meaning that the thread cannot change the contents. That'd be
     * unsafe */
    const XConf  *xconf;
    Scanner      *scanner;
    PACKET_QUEUE *handle_queue;
    STACK        *stack;
    OutConf      *out_conf;
    uint64_t      entropy;
    /*unique index of the handle thread that count from 0*/
    unsigned      index;
} HandleConf;

static void handle_thread(void *v) {
    HandleConf  *parms = v;
    const XConf *xconf = parms->xconf;

    LOG(LEVEL_DEBUG, "starting handle thread #%u\n", parms->index);

    char th_name[30];
    snprintf(th_name, sizeof(th_name), XTATE_NAME "-hdl #%u", parms->index);
    pixie_set_thread_name(th_name);

    /* Lock threads to the CPUs one by one in this order:
     *     1.Tx threads
     *     2.Rx thread
     *     3.Rx handle threads
     * TODO: Make CPU locking be settable.
     */
    if (pixie_cpu_get_count() > 1 && !xconf->is_no_cpu_bind) {
        unsigned cpu_count = pixie_cpu_get_count();
        unsigned cpu_index = xconf->tx_thread_count + parms->index + 1;
        /* I think it is better to make (cpu>=cpu_count) threads free */
        if (cpu_index < cpu_count)
            pixie_cpu_set_affinity(cpu_index);
    }

    while (!time_to_finish_rx) {
        /**
         * Do polling for scan module in each loop
         */
        parms->scanner->poll_cb(parms->index);

        Recved *recved = NULL;
        int err = rte_ring_sc_dequeue(parms->handle_queue, (void **)&recved);
        if (err != 0) {
            pixie_usleep(RTE_XTATE_DEQ_USEC);
            continue;
        }

        if (recved == NULL) {
            LOG(LEVEL_ERROR,
                "got empty Recved in handle thread #%d. (IMPOSSIBLE)\n",
                parms->index);
            fflush(stdout);
            exit(1);
        }

        OutItem item = {
            .target.ip_proto  = recved->parsed.ip_protocol,
            .target.ip_them   = recved->parsed.src_ip,
            .target.ip_me     = recved->parsed.dst_ip,
            .target.port_them = recved->parsed.port_src,
            .target.port_me   = recved->parsed.port_dst,
        };

        parms->scanner->handle_cb(parms->index, parms->entropy, recved, &item,
                                  parms->stack);

        output_result(parms->out_conf, &item);

        FREE(recved->packet);
        FREE(recved);
    }

    LOG(LEVEL_DEBUG, "exiting handle thread #%u                    \n",
        parms->index);
}

void receive_thread(void *v) {
    RxThread        *parms        = (RxThread *)v;
    const XConf     *xconf        = parms->xconf;
    OutConf         *out_conf     = (OutConf *)(&xconf->out_conf);
    Adapter         *adapter      = xconf->nic.adapter;
    int              data_link    = stack_if_datalink(adapter);
    uint64_t         entropy      = xconf->seed;
    STACK           *stack        = xconf->stack;
    Scanner         *scan_module  = xconf->scanner;
    Dedup           *dedup        = NULL;
    struct PcapFile *pcapfile     = NULL;
    unsigned         handler_num  = xconf->rx_handler_count;
    size_t          *handler      = MALLOC(handler_num * sizeof(size_t));
    HandleConf      *handle_parms = MALLOC(handler_num * sizeof(HandleConf));
    PACKET_QUEUE   **handle_q = MALLOC(handler_num * sizeof(PACKET_QUEUE *));
    size_t           dispatcher;
    DispatchConf     dispatch_parms;
    PACKET_QUEUE    *dispatch_q;
    Recved          *recved;

    LOG(LEVEL_DEBUG, "starting receive thread\n");

    pixie_set_thread_name(XTATE_NAME "-recv");

    if (xconf->is_offline) {
        while (!time_to_finish_rx)
            pixie_usleep(10000);
        parms->done_receiving = true;
        return;
    }

    /* Lock threads to the CPUs one by one in this order:
     *     1.Tx threads
     *     2.Rx thread
     *     3.Rx handle threads
     * TODO: Make CPU locking be settable.
     */
    if (pixie_cpu_get_count() > 1 && !xconf->is_no_cpu_bind) {
        unsigned cpu_count = pixie_cpu_get_count();
        unsigned cpu_index = xconf->tx_thread_count;
        /* I think it is better to make (cpu>=cpu_count) threads free */
        if (cpu_index < cpu_count)
            pixie_cpu_set_affinity(cpu_index);
    }

    if (xconf->pcap_filename[0]) {
        pcapfile = pcapfile_openwrite(xconf->pcap_filename, 1);
    }

    if (!xconf->is_nodedup)
        dedup = dedup_init(xconf->dedup_win);

    /**
     * init dispatch and handle threads
     */
    dispatch_q = rte_ring_create(xconf->dispatch_buf_count,
                                 RING_F_SP_ENQ | RING_F_SC_DEQ);
    for (unsigned i = 0; i < handler_num; i++) {
        handle_q[i] = rte_ring_create(xconf->dispatch_buf_count,
                                      RING_F_SP_ENQ | RING_F_SC_DEQ);
    }

    parms->dispatch_q = dispatch_q;
    parms->handle_q   = handle_q;

    dispatch_parms.entropy          = entropy;
    dispatch_parms.handle_queue     = handle_q;
    dispatch_parms.dispatch_queue   = dispatch_q;
    dispatch_parms.recv_handle_num  = handler_num;
    dispatch_parms.recv_handle_mask = handler_num - 1;

    dispatcher = pixie_begin_thread(dispatch_thread, 0, &dispatch_parms);

    for (unsigned i = 0; i < handler_num; i++) {
        handle_parms[i].scanner      = xconf->scanner;
        handle_parms[i].handle_queue = handle_q[i];
        handle_parms[i].xconf        = xconf;
        handle_parms[i].stack        = stack;
        handle_parms[i].out_conf     = out_conf;
        handle_parms[i].entropy      = entropy;
        handle_parms[i].index        = i;

        handler[i] = pixie_begin_thread(handle_thread, 0, &handle_parms[i]);
    }

    LOG(LEVEL_DEBUG, "(rx thread) starting main loop\n");
    while (!time_to_finish_rx) {
        unsigned             pkt_len, pkt_secs, pkt_usecs;
        const unsigned char *pkt_data;

        int err = rawsock_recv_packet(adapter, &pkt_len, &pkt_secs, &pkt_usecs,
                                      &pkt_data);
        if (err != 0) {
            continue;
        }
        if (pkt_len > xconf->max_packet_len) {
            continue;
        }

        /**
         * recved will not be handle in this thread.
         * and packet received from Adapters cannot exist too long.
         */
        recved         = CALLOC(1, sizeof(Recved));
        recved->packet = MALLOC(pkt_len);
        recved->length = pkt_len;
        recved->secs   = pkt_secs;
        recved->usecs  = pkt_usecs;
        memcpy(recved->packet, pkt_data, pkt_len);

        unsigned x = preprocess_frame(recved->packet, recved->length, data_link,
                                      &recved->parsed);
        if (!x) {
            FREE(recved->packet);
            FREE(recved);
            continue; /* corrupt packet */
        }

        ipaddress ip_them   = recved->parsed.src_ip;
        ipaddress ip_me     = recved->parsed.dst_ip;
        unsigned  port_them = recved->parsed.port_src;
        unsigned  port_me   = recved->parsed.port_dst;

        assert(ip_me.version != 0);
        assert(ip_them.version != 0);

        recved->is_myip   = is_my_ip(stack->src, ip_me);
        recved->is_myport = is_my_port(stack->src, port_me);

        /**
         * Do response for special arp&ndp packets while bypassing OS protocol
         * stack to announce our existing.
         */
        if (xconf->is_bypass_os) {
            /*NDP Neighbor Solicitations to a multicast address */
            if (!recved->is_myip && is_ipv6_multicast(ip_me) &&
                recved->parsed.found == FOUND_NDPv6 &&
                recved->parsed.icmp_type == ICMPv6_TYPE_NS) {
                stack_ndpv6_incoming_request(stack, &recved->parsed,
                                             recved->packet, recved->length);
            }

            if (recved->is_myip) {
                if (recved->parsed.found == FOUND_NDPv6 &&
                    recved->parsed.icmp_type == ICMPv6_TYPE_NS) {
                    /* When responses come back from our scans, the router will
                     * send us these packets. We need to respond to them, so
                     * that the router can then forward the packets to us. If we
                     * don't respond, we'll get no responses. */
                    stack_ndpv6_incoming_request(
                        stack, &recved->parsed, recved->packet, recved->length);
                }
                if (recved->parsed.found == FOUND_ARP &&
                    recved->parsed.arp_info.opcode == ARP_OPCODE_REQUEST) {
                    /* This function will transmit a "reply" to somebody's ARP
                     * request for our IP address (as part of our user-mode
                     * TCP/IP). Since we completely bypass the TCP/IP stack, we
                     * have to handle ARPs ourself, or the router will lose
                     * track of us.*/
                    stack_arp_incoming_request(stack, ip_me.ipv4,
                                               stack->source_mac,
                                               recved->packet, recved->length);
                }
            }
        }

        PreHandle pre = {
            .dedup_ip_them   = ip_them,
            .dedup_port_them = port_them,
            .dedup_ip_me     = ip_me,
            .dedup_port_me   = port_me,
            .dedup_type      = SM_DFT_DEDUP_TYPE,
        };

        scan_module->validate_cb(entropy, recved, &pre);

        if (!pre.go_record) {
            FREE(recved->packet);
            FREE(recved);
            continue;
        }

        if (parms->xconf->is_packet_trace)
            packet_trace(stdout, parms->pt_start, recved->packet,
                         recved->length, false);

        /* Save raw packet in --pcap file */
        if (pcapfile && !pre.no_record) {
            pcapfile_writeframe(pcapfile, recved->packet, recved->length,
                                recved->length, recved->secs, recved->usecs);
        }

        if (!pre.go_dedup) {
            FREE(recved->packet);
            FREE(recved);
            continue;
        }

        if (!xconf->is_nodedup && !pre.no_dedup) {
            if (dedup_is_dup(dedup, pre.dedup_ip_them, pre.dedup_port_them,
                             pre.dedup_ip_me, pre.dedup_port_me,
                             pre.dedup_type)) {
                FREE(recved->packet);
                FREE(recved);
                continue;
            }
        }

        /**
         * give it to dispatcher
         */
        for (err = 1; err != 0;) {
            err = rte_ring_sp_enqueue(dispatch_q, recved);
            if (err != 0) {
                LOG(LEVEL_ERROR,
                    "dispatch queue full from rx thread with too fast rate.\n");
                pixie_usleep(RTE_XTATE_ENQ_USEC);
                // exit(1);
            }
        }
    }

    LOG(LEVEL_DEBUG,
        "exiting receive thread and joining handlers               \n");

    /*
     * cleanup
     */

    /*stop reader and handlers*/
    pixie_thread_join(dispatcher);
    for (unsigned i = 0; i < handler_num; i++) {
        pixie_thread_join(handler[i]);
    }

    if (!xconf->is_nodedup && dedup) {
        dedup_close(dedup);
        dedup = NULL;
    }
    if (pcapfile) {
        pcapfile_close(pcapfile);
        pcapfile = NULL;
    }
    if (dispatch_q) {
        parms->handle_q = NULL;
    }
    FREE(handler);
    FREE(handle_parms);
    FREE(handle_q);

    /* Thread is about to exit */
    parms->done_receiving = true;
}

#include "stack-queue.h"
#include "../pixie/pixie-timer.h"
#include "../rawsock/rawsock.h"
#include "../util-data/fine-malloc.h"
#include "../util-out/logger.h"
#include <string.h>
#include <stdio.h>

PktBuf *
stack_get_pktbuf(STACK *stack)
{
    PktBuf *response = NULL;

    int err = rte_ring_mc_dequeue(stack->packet_buffers, (void**)&response);

    if (err!=0) {
        //!No need to proceed
        LOG(LEVEL_ERROR, "failed to get packet buffer. (IMPOSSIBLE)\n");
        fflush(stdout);
        exit(1);
    }

    if (response == NULL) {
        //!No need to proceed
        LOG(LEVEL_ERROR, "got empty packet buffer. (IMPOSSIBLE)\n");
        fflush(stdout);
        exit(1);
    }

    return response;
}

void
stack_transmit_pktbuf(STACK *stack, PktBuf *response)
{
    int err;
    for (err=1; err; ) {
        err = rte_ring_mp_enqueue(stack->transmit_queue, response);
        if (err) {
            LOG(LEVEL_ERROR, "transmit queue full (should be impossible)\n");
            pixie_usleep(1000);
        }
    }
}

/***************************************************************************
 * The receive thread doesn't transmit packets. Instead, it queues them
 * up on the transmit thread. Every so often, the transmit thread needs
 * to flush this transmit queue and send everything.
 *
 * This is an inherent design issue trying to send things as batches rather
 * than individually. It increases latency, but increases performance. We
 * don't really care about latency.
 ***************************************************************************/
void
stack_flush_packets(
    STACK *stack,
    Adapter *adapter,
    AdapterCache *acache,
    uint64_t *packets_sent,
    uint64_t *batchsize)
{
    /*
     * Send a batch of queued packets
     */
    for ( ; (*batchsize); (*batchsize)--) {
        int err;
        PktBuf *p;

        /*
         * Get the next packet from the transmit queue. This packet was
         * put there by a receive thread, and will contain things like
         * an ACK or an HTTP request
         */
        err = rte_ring_mc_dequeue(stack->transmit_queue, (void**)&p);
        if (err!=0) {
            break; /* queue is empty, nothing to send */
        }


        /*
         * Actually send the packet.
         * We won't flush there but outside the function.
         */
        rawsock_send_packet(adapter, acache, p->px, (unsigned)p->length);

        /*
         * Now that we are done with the packet, put it on the free list
         * of buffers that the transmit thread can reuse
         */
        err = rte_ring_mp_enqueue(stack->packet_buffers, p);
        if (err!=0) {
            //!No need to proceed
            LOG(LEVEL_ERROR, "transmit queue full from `stack_flush_packets` (should be impossible).\n");
            exit(1);
        }

        /*
         * Remember that we sent a packet, which will be used in
         * throttling.
         */
        (*packets_sent)++;
    }

}

STACK *
stack_create(macaddress_t source_mac, StackSrc *src, unsigned buf_count)
{
    STACK *stack;
    size_t i;

    stack = CALLOC(1, sizeof(*stack));
    stack->source_mac = source_mac;
    stack->src = src;

    /*
     * NOTE:
     * We must consider multi-providers and multi-consumers now
     */
    stack->packet_buffers = rte_ring_create(buf_count, 0);
    stack->transmit_queue = rte_ring_create(buf_count, 0);
    for (i=0; i<buf_count-1; i++) {
        PktBuf *p;
        int err;

        p   = MALLOC(sizeof(*p));
        err = rte_ring_sp_enqueue(stack->packet_buffers, p);
        if (err) {
            /* I dunno why but I can't queue all 256 packets, just 255 */
            LOG(LEVEL_ERROR, "packet_buffers: enqueue: error %d\n", err);
        }
    }

    return stack;
}




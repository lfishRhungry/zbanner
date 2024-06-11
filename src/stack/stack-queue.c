#include "stack-queue.h"
#include "../pixie/pixie-timer.h"
#include "../rawsock/rawsock.h"
#include "../util-data/fine-malloc.h"
#include "../util-out/logger.h"
#include <string.h>
#include <stdio.h>

struct PacketBuffer *
stack_get_packetbuffer(struct stack_t *stack)
{
    int err;
    struct PacketBuffer *response = NULL;

    for (err=1; err; ) {
        err = rte_ring_mc_dequeue(stack->packet_buffers, (void**)&response);
        if (err != 0) {
            /* Pause and wait for a buffer to become available */
            pixie_usleep(1000);
        }
    }

    if (response == NULL) {
        LOG(LEVEL_ERROR, "FAIL: packet buffers empty. (IMPOSSIBLE)\n");
        fflush(stdout);
        exit(1);
    }
    return response;
}

void
stack_transmit_packetbuffer(struct stack_t *stack, struct PacketBuffer *response)
{
    int err;
    for (err=1; err; ) {
        err = rte_ring_mp_enqueue(stack->transmit_queue, response);
        if (err) {
            LOG(LEVEL_ERROR, "[-] transmit queue full (should be impossible)\n");
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
    struct stack_t *stack,
    struct Adapter *adapter,
    struct AdapterCache *acache,
    uint64_t *packets_sent,
    uint64_t *batchsize)
{
    /*
     * Send a batch of queued packets
     */
    for ( ; (*batchsize); (*batchsize)--) {
        int err;
        struct PacketBuffer *p;

        /*
         * Get the next packet from the transmit queue. This packet was
         * put there by a receive thread, and will contain things like
         * an ACK or an HTTP request
         */
        err = rte_ring_mc_dequeue(stack->transmit_queue, (void**)&p);
        if (err) {
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
        for (err=1; err; ) {
            err = rte_ring_mp_enqueue(stack->packet_buffers, p);
            if (err) {
                LOG(LEVEL_ERROR, "[-] transmit queue full (should be impossible)\n");
                pixie_usleep(10000);
            }
        }

        /*
         * Remember that we sent a packet, which will be used in
         * throttling.
         */
        (*packets_sent)++;
    }

}

struct stack_t *
stack_create(macaddress_t source_mac, struct stack_src_t *src, unsigned buf_count)
{
    struct stack_t *stack;
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
        struct PacketBuffer *p;
        int err;

        p = MALLOC(sizeof(*p));
        err = rte_ring_sp_enqueue(stack->packet_buffers, p);
        if (err) {
            /* I dunno why but I can't queue all 256 packets, just 255 */
            LOG(LEVEL_ERROR, "[-] packet_buffers: enqueue: error %d\n", err);
        }
    }

    return stack;
}




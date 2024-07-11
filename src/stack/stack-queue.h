#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H
#include "../util-data/rte-ring.h"
#include "../target/target-addr.h"
#include <limits.h>

/**It limits the max size of packet we could send
 * and affects what value we set on PM_PAYLOAD_SIZE
 */
#define PKT_BUF_SIZE 2048

typedef struct StackOfSource StackSrc;
typedef struct Adapter       Adapter;
typedef struct Adapter_Cache AdapterCache;

typedef struct rte_ring PACKET_QUEUE;

typedef struct PacketBuffer {
    size_t        length;
    unsigned char px[PKT_BUF_SIZE];
} PktBuf;

typedef struct StackWithQueue {
    PACKET_QUEUE *packet_buffers;
    PACKET_QUEUE *transmit_queue;
    macaddress_t  source_mac;
    StackSrc     *src;
} STACK;

/**
 * Get a packet-buffer that we can use to create a packet for sending.
 * NOTE: It would return a non-null value or exit our process.
 */
PktBuf *stack_get_pktbuf(STACK *stack);

/**
 * Queue up the packet for sending. This doesn't send the packet immediately,
 * but puts it into a queue to be sent later, when the throttler allows it
 * to be sent.
 */
void stack_transmit_pktbuf(STACK *stack, PktBuf *response);

void stack_flush_packets(STACK *stack, Adapter *adapter, AdapterCache *acache,
                         uint64_t *packets_sent, uint64_t *batchsize);

STACK *stack_create(macaddress_t source_mac, StackSrc *src, unsigned buf_count);

#endif

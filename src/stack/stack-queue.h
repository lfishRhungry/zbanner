#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include <limits.h>

#include "stack-src.h"
#include "../util-data/rte-ring.h"
#include "../target/target-ipaddress.h"

/**It limits the max size of packet we could send
 * and affects what value we set on PM_PAYLOAD_SIZE
 */
#define PKT_BUF_SIZE 2048

struct NetworkAdapter;
struct Adapter_Cache;

typedef struct rte_ring PktQueue;

typedef struct PacketBuffer {
    size_t        length;
    unsigned char px[PKT_BUF_SIZE];
} PktBuf;

typedef struct NetworkStack {
    PktQueue    *packet_buffers;
    PktQueue    *transmit_queue;
    macaddress_t source_mac;
    StackSrc    *src;
} NetStack;

/**
 * Get a packet-buffer that we can use to create a packet for sending.
 * NOTE: It would return a non-null value or exit our process.
 */
PktBuf *stack_get_pktbuf(NetStack *stack);

/**
 * Queue up the packet for sending. This doesn't send the packet immediately,
 * but puts it into a queue to be sent later, when the throttler allows it
 * to be sent.
 */
void stack_transmit_pktbuf(NetStack *stack, PktBuf *response);

void stack_flush_packets(NetStack *stack, struct NetworkAdapter *adapter,
                         struct Adapter_Cache *acache, uint64_t *packets_sent,
                         uint64_t *batchsize);

NetStack *stack_create(macaddress_t source_mac, StackSrc *src,
                       unsigned buf_count);

#endif

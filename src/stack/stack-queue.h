#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H
#include "../util-data/rte-ring.h"
#include "../massip/massip-addr.h"
#include <limits.h>

/**It limits the max size of packet we could send
 * and affects what value we set on PROBE_PAYLOAD_MAX_LEN
*/
#define PKT_BUF_LEN     2048

struct stack_src_t;
struct Adapter;
struct AdapterCache;

typedef struct rte_ring PACKET_QUEUE;

struct PacketBuffer {
    size_t length;
    unsigned char px[PKT_BUF_LEN];
};

struct stack_t {
    PACKET_QUEUE *packet_buffers;
    PACKET_QUEUE *transmit_queue;
    macaddress_t source_mac;
    struct stack_src_t *src;
};

/**
 * Get a packet-buffer that we can use to create a packet for sending.
 * NOTE: It would return a non-null value or exit our process.
 */
struct PacketBuffer *
stack_get_packetbuffer(struct stack_t *stack);

/**
 * Queue up the packet for sending. This doesn't send the packet immediately,
 * but puts it into a queue to be sent later, when the throttler allows it
 * to be sent.
 */
void
stack_transmit_packetbuffer(struct stack_t *stack, struct PacketBuffer *response);

void
stack_flush_packets(
    struct stack_t *stack,
    struct Adapter *adapter,
    struct AdapterCache *acache,
    uint64_t *packets_sent,
    uint64_t *batchsize);

struct stack_t *
stack_create(macaddress_t source_mac, struct stack_src_t *src, unsigned buf_count);

#endif

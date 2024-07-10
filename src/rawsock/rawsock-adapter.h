#ifndef RAWSOCK_ADAPTER_H
#define RAWSOCK_ADAPTER_H

#define SENDQ_SIZE      65536 * 8

typedef struct Adapter
{
    struct pcap                *pcap;
    struct __pfring            *ring;
    unsigned                    is_packet_trace:1;
    unsigned                    is_vlan:1;
    unsigned                    vlan_id;
    double                      pt_start;
    int                         link_type;
} Adapter;

/**
 * For every Tx thread to maintain its own cache for sendqueue or sendmmsg.
 * This solves the conflict while multiple Tx threads using sendqueue mechanism.
 */
typedef struct Adapter_Cache
{
    struct pcap_send_queue     *sendq;
} AdapterCache;

AdapterCache *
rawsock_init_cache(bool is_sendq);

void
rawsock_close_cache(AdapterCache *acache);


/**
 * Retrieve the datalink type of the adapter
 */
int
stack_if_datalink(Adapter *adapter);

#endif

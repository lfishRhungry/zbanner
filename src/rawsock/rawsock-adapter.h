#ifndef RAWSOCK_ADAPTER_H
#define RAWSOCK_ADAPTER_H

#define SENDQ_SIZE      65536 * 8

struct Adapter
{
    struct pcap                *pcap;
    struct __pfring            *ring;
    unsigned                    is_packet_trace:1; /* is --packet-trace option set? */
    unsigned                    is_vlan:1;
    unsigned                    vlan_id;
    double                      pt_start;
    int                         link_type;
};

/**
 * For every Tx thread to maintain its own cache for sendqueue or sendmmsg.
 */
struct AdapterCache
{
    struct pcap_send_queue     *sendq;
};

struct AdapterCache *
rawsock_init_cache(bool is_sendq);

void
rawsock_close_cache(struct AdapterCache *acache);


/**
 * Retrieve the datalink type of the adapter
 *
 *  1 = Ethernet
 * 12 = Raw IP (no datalink)
 */
int
stack_if_datalink(struct Adapter *adapter);

#endif

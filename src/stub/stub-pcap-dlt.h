#ifndef STUB_PCAP_DLT_H
#define STUB_PCAP_DLT_H

/**
 * ref: https://www.tcpdump.org/linktypes.html
 * ref: https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
 */
typedef enum {
    /* Packets are prefixed by an integer indicating
     * the protocol type in host-byte-order (4-bytes)
     * followed by the raw IPv4 or IPv6 header */
    PCAP_DLT_NULL     = 0,
    /* Ethernet */
    PCAP_DLT_ETHERNET = 1,
    /* Packets are 'raw' on the network. The first byte
     * will be the first byte of the IPv4/IPv6 header */
    PCAP_DLT_RAW      = 12,
} pcap_dlt_t;

#endif


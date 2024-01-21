/**
 * SCAN MODULES make you send and handle raw packet with
 * Xtate easily.
 * 
 * NOTE: It's a multi-thread process internally.
 * Keep your modules thread-safe!
*/
#ifndef SCAN_MODULES
#define SCAN_MODULES

#include <stdlib.h>
#include <ctype.h>

#include "../massip/massip-addr.h"
#include "../proto/proto-preprocess.h"
#include "../templ/templ-pkt.h"

#define SCAN_MODULE_ARGS_LEN 50

/**
 * * callback functions for Init
*/

/**
 * We always do some initialization here,
 * especially prepare the packet template.
 * I provide some params set in xtate for all ScanModules.
 * You could use them as you like.
 * @param tmpl_pkt set this (initialized) packet template for some fixed features.
 * @param source_mac our mac addr.
 * @param router_mac_ipv4 our gateway mac for ipv4 packet sending.
 * @param router_mac_ipv6 out gateway mac for ipv6 packet sending.
 * @param udp_payloads user-specified UDP payload.
 * @param oproto_payloads user-specified payload for other UDP packet.
 * @param data_link data link type of adapter (1 for eth, 12 for raw IP).
 * @param templ_opts user-specified packet options like ttl, mss and etc. (NULL if no specified)
 * @return EXIT_FAILURE for initing failed and exit process.
*/
typedef int (*scan_modules_global_init)(
    struct TemplatePacket *tmpl_pkt, macaddress_t source_mac,
    macaddress_t router_mac_ipv4, macaddress_t router_mac_ipv6,
    struct PayloadsUDP *udp_payloads, struct PayloadsUDP *oproto_payloads, 
    int data_link, const struct TemplateOptions *templ_opts);

/**
 * @return EXIT_FAILURE for initing failed and exit process.
*/
typedef int (*scan_modules_rxthread_init)();

/**
 * @return EXIT_FAILURE for initing failed and exit process.
*/
typedef int (*scan_modules_txthread_init)();

/**
 * * callback functions for Transmit
*/

/**
 * It happens in Tx Thread
 * @param tmpl_pkt packet template we have prepared in global init.
 * @param ip_them IP of this target.
 * @param port_them Port of this target (if port is meaningful).
 * @param ip_me IP of us.
 * @param port_me Port of us (if port is meaningful).
 * @param entropy a rand seed (generated or user-specified).
 * @param index This is the index times to send the packet
 * for this target in tx_thread (not through callback queue).
 * @param px Load your packet data to here.
 * @param px_length Length of buffer.
 * @param r_length Length of returned packet length.
 * @return TRUE if need to send packet to for target in tx_thread again.
*/
typedef int (*scan_modules_make_new_packet_ipv4)(
    struct TemplatePacket *tmpl_pkt,
    ipv4address ip_them, unsigned port_them,
    ipv4address ip_me, unsigned port_me,
    uint64_t entropy, unsigned index,
    unsigned char *px, unsigned px_length, size_t *r_length);

/**
 * It happens in Tx Thread
 * @param tmpl_pkt packet template we have prepared in global init.
 * @param ip_them IP of this target.
 * @param port_them Port of this target (if port is meaningful).
 * @param ip_me IP of us.
 * @param port_me Port of us (if port is meaningful).
 * @param entropy a rand seed (generated or user-specified).
 * @param index This is the index times to send the packet
 * for this target in tx_thread (not through callback queue).
 * @param px Load your packet data to here.
 * @param px_length Length of buffer.
 * @param r_length Length of returned packet length.
 * @return TRUE if need to send packet to for target in tx_thread again.
*/
typedef int (*scan_modules_make_new_packet_ipv6)(
    struct TemplatePacket *tmpl_pkt,
    ipv6address ip_them, unsigned port_them,
    ipv6address ip_me, unsigned port_me,
    uint64_t entropy, unsigned index,
    unsigned char *px, unsigned px_length, size_t *r_length);

/**
 * * callback functions for Receive
*/

/**
 * Step 1 Validate: Is this packet need to be handle?
 * @param parsed Parsed info about this packet.
 * @return is this a valid packet for this ScanModule to handle (and save to pcap file)?
*/
typedef int (*scan_modules_validate_packet)(struct PreprocessedInfo *parsed);

/**
 * Step 2 Decuplicate: Is and how this packet to be deduped?
 * @param parsed Parsed info about this packet.
 * @return Zero for no dedup or an unsigned for a dedup type.
*/
typedef unsigned (*scan_modules_dedup_packet)(struct PreprocessedInfo *parsed);

/**
 * Step 2 Handle: 
 * @param parsed Parsed info about this packet.
 * @param px Put data of packet need to be sent here.
 * @param px_length Length of buffer that px points.
 * @param successed Is this packet considered success.
 * @param classification Packet classification string.
 * @param cls_length Length of classification string buffer.
 * @param px Put data of packet need to be sent here.
 * @param px_length Length of buffer that px points.
 * @param index This is the index times to send the packet
 * for this target in tx_thread (not through callback queue).
 * @return TRUE if need to response.
*/
typedef int (*scan_modules_handle_packet)(
    struct PreprocessedInfo *parsed, unsigned *successed,
    char *classification, unsigned cls_length);

/**
 * Step 3 Response: 
 * @param px Put data of packet need to be sent here.
 * @param px_length Length of buffer that px points.
 * @param index This is the index times to response.
 * @return TRUE if need to response.
*/
typedef int (*scan_modules_make_response_packet)(
    unsigned char *px, unsigned px_length, unsigned index);

/**
 * * callback functions for Close
*/

/**
 * It happens before normal exit in mainscan function.
*/
typedef void (*scan_modules_close)();


struct ScanModule
{
    const char *name;
    const char *description;

    /*for init*/
    scan_modules_global_init global_init_cb;
    scan_modules_rxthread_init rx_thread_init_cb;
    scan_modules_txthread_init tx_thread_init_cb;

    /*for transmit*/
    scan_modules_make_new_packet_ipv4 make_packet_ipv4_cb;
    scan_modules_make_new_packet_ipv6 make_packet_ipv6_cb;

    /*for receive*/
    scan_modules_validate_packet validate_packet_cb;
    scan_modules_dedup_packet dedup_packet_cb;
    scan_modules_handle_packet handle_packet_cb;
    scan_modules_make_response_packet response_packet_cb;

    /*for close*/
    scan_modules_close close_cb;
};

struct ScanModule *get_scan_module_by_name(const char *name);

void list_all_scan_modules();

#endif
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

#include "../param-configer.h"
#include "../massip/massip-addr.h"
#include "../proto/proto-preprocess.h"
#include "../stack/stack-queue.h"

/**
 * @param Xconf struct Xconf.
 * xconf.h need to includes this file
 * and struct Xconf/Thread must be used here.
 * Use 'void' to avoid circular dependency,
 * cast it to correct type in specific implementation of probe.
 * @return EXIT_FAILURE to exit process if init failed
*/
typedef int (*scan_modules_global_init)(const void *Xconf);

/**
 * @param RxThread struct TxThread.
 * @return EXIT_FAILURE to exit process if init failed
*/
typedef int (*scan_modules_rxthread_init)(const void *RxThread);

/**
 * @param TxThread struct TxThread.
 * @return EXIT_FAILURE to exit process if init failed
*/
typedef int (*scan_modules_txthread_init)(const void *TxThread);

/**
 * It happens in Tx Thread
 * @param ip_them IP of this target.
 * @param port_them Port of this target (if port is meaningful).
 * @param ip_me IP of us.
 * @param port_me Port of us (if port is meaningful).
 * @param px Load your packet data to here.
 * @param px_length Length of buffer.
 * @param index This is the index times to send the packet
 * for this target in tx_thread (not through callback queue).
 * @return TRUE if need to send packet to for target in tx_thread again.
*/
typedef int (*scan_modules_make_packet_ipv4)(
    ipv4address ip_them, unsigned port_them,
    ipv4address ip_me, unsigned port_me,
    unsigned char *px, unsigned px_length,
    unsigned index);

/**
 * It happens in Tx Thread
 * @param ip_them IP of this target.
 * @param port_them Port of this target (if port is meaningful).
 * @param ip_me IP of us.
 * @param port_me Port of us (if port is meaningful).
 * @param px Load your packet data to here.
 * @param px_length Length of buffer.
 * @param index This is the index times to send the packet
 * for this target in tx_thread (not through callback queue).
 * @return TRUE if need to send packet to for target in tx_thread again.
*/
typedef int (*scan_modules_make_packet_ipv6)(
    ipv4address ip_them, unsigned port_them,
    ipv4address ip_me, unsigned port_me,
    unsigned char *px, unsigned px_length,
    unsigned index);

/**
 * It happens in Rx Thread.
 * @param parsed Parsed info about this packet.
 * @param send_queue Put packet to this queue for transmit.
 * @param successed Is this packet considered success.
 * @param classification Packet classification string.
 * @param cls_length Length of classification string buffer.
*/
typedef void (*scan_modules_handle_packet)(
    struct PreprocessedInfo *parsed, struct stack_t *send_queue,
    unsigned *successed, char *classification, unsigned cls_length);


struct ScanModule
{
    const char *name;
    const char *description;
    const struct ConfigParameter *config_param_list;
    
    scan_modules_global_init global_init;
    scan_modules_rxthread_init rx_thread_init;
    scan_modules_txthread_init tx_thread_init;

    scan_modules_make_packet_ipv4 make_packet_ipv4;
    scan_modules_make_packet_ipv6 make_packet_ipv6;

    scan_modules_handle_packet handle_packet;
};

struct ScanModule *get_scan_by_name(const char *name);

void list_all_scans();

#endif
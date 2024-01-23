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


#define SCAN_MODULE_CLS_LEN            15
#define SCAN_MODULE_RPT_LEN          1460
#define SCAN_MODULE_ARGS_LEN           50
#define SCAN_MODULE_DEFAULT_DEDUP_TYPE  0

/***************************************************************************
 * * callback functions for Init
****************************************************************************/

/**
 * Do some initialization here if you have to.
 * NOTE: Xtate had init many packet templates. But you can change
 * the template set by specific options.
 * @param tmplset packet template Xtate had prepared most of transmit protocol.
 * @return false for initing failed and exit process.
*/
typedef int (*scan_modules_global_init)(struct TemplateSet *tmplset);

/**
 * @return false for initing failed and exit process.
*/
typedef int (*scan_modules_rxthread_init)();

/**
 * @return false for initing failed and exit process.
*/
typedef int (*scan_modules_txthread_init)();

/***************************************************************************
 * * callback functions for Transmit
****************************************************************************/

/**
 * Happens in Tx Thread
 * 
 * @param tmplset packet template Xtate had prepared most of transmit protocol.
 * @param ip_them IP of this target.
 * @param port_them Port of this target (if port is meaningful).
 * @param ip_me IP of us.
 * @param port_me Port of us (if port is meaningful).
 * @param entropy a rand seed (generated or user-specified).
 * @param index This is the index times to send the packet
 * for this target in tx_thread (not through callback queue).
 * @param px Load your packet data to here.
 * @param sizeof_px Length of buffer.
 * @param r_length Length of returned packet length (doesn't send anything if zero).
 * 
 * @return true for this target in tx_thread again.
*/
typedef int (*scan_modules_make_new_packet)(
    struct TemplateSet *tmplset,
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    uint64_t entropy, unsigned index,
    unsigned char *px, unsigned sizeof_px, size_t *r_length);

/***************************************************************************
 * * callback functions for Receive
****************************************************************************/

/**
 * Step 1 Filter: Is this packet need to be record (to pcap)
 * and possibly validate in next step?
 * 
 * @param parsed Parsed info about this packet.
 * @param entropy a rand seed (generated or user-specified).
 * @param px point to packet data.
 * @param sizeof_px length of packet data.
 * @param is_myip for reference
 * @param is_myport for reference
 * 
 * @return true for this ScanModule to handle (and save to pcap file)
 * and go on Step 2?
*/
typedef int (*scan_modules_filter_packet)(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned is_myip, unsigned is_myport);

/**
 * Step 2 Validate: Is this packet need to be handle?
 * 
 * @param parsed Parsed info about this packet.
 * @param entropy a rand seed (generated or user-specified).
 * @param px point to packet data.
 * @param sizeof_px length of packet data.
 * 
 * @return true for this ScanModule to go on to dedup meaningfully in Step 3?
*/
typedef int (*scan_modules_validate_packet)(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px);

/**
 * Step 3 Decuplicate: Is and how this packet to be deduped?
 * 
 * @param parsed Parsed info about this packet.
 * @param entropy a rand seed (generated or user-specified).
 * @param px point to packet data.
 * @param sizeof_px length of packet data.
 * @param type dedup type for keep same (ip_them, port_them, ip_me, port_me) packet in diff type.
 * 
 * @return false for nodedup
*/
typedef int (*scan_modules_dedup_packet)(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned *type);

/**
 * Step 4 Handle
 * 
 * @param parsed Parsed info about this packet.
 * @param entropy a rand seed (generated or user-specified).
 * @param px point to packet data.
 * @param sizeof_px length of packet data.
 * @param successed Is this packet considered success.
 * @param classification Packet classification string.
 * @param cls_length Length of classification string buffer.
 * @param report Report string.
 * @param rpt_length Length of report string buffer.
 * 
 * @return true if need to response in Step 5.
*/
typedef int (*scan_modules_handle_packet)(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned *successed,
    char *classification, unsigned cls_length,
    char *report, unsigned rpt_length);


/**
 * Step 5 Response
 * 
 * @param tmplset packet template Xtate had prepared most of transmit protocol.
 * @param parsed Parsed info about this packet.
 * @param entropy a rand seed (generated or user-specified).
 * @param px point to packet data.
 * @param sizeof_px length of packet data.
 * @param r_px Put data of packet need to be sent here.
 * @param sizeof_r_px Length of buffer that px points.
 * @param r_length Length of returned packet length (doesn't send anything if zero).
 * @param index This is the index times to response.
 * 
 * @param return true if need to do more response.
*/
typedef int (*scan_modules_make_response_packet)(
    struct TemplateSet *tmplset,
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned char *r_px, unsigned sizeof_r_px,
    size_t *r_length, unsigned index);

/***************************************************************************
 * * callback functions for Close
****************************************************************************/

/**
 * It happens before normal exit in mainscan function.
*/
typedef void (*scan_modules_close)();


struct ScanModule
{
    const char *                      name;
    const char *                      description;
    /*for init*/
    scan_modules_global_init          global_init_cb;
    scan_modules_rxthread_init        rx_thread_init_cb;
    scan_modules_txthread_init        tx_thread_init_cb;
    /*for transmit*/
    scan_modules_make_new_packet      make_packet_cb;
    /*for receive*/
    scan_modules_filter_packet        filter_packet_cb;
    scan_modules_validate_packet      validate_packet_cb;
    scan_modules_dedup_packet         dedup_packet_cb;
    scan_modules_handle_packet        handle_packet_cb;
    scan_modules_make_response_packet response_packet_cb;
    /*for close*/
    scan_modules_close                close_cb;
};

struct ScanModule *get_scan_module_by_name(const char *name);

void list_all_scan_modules();

#endif
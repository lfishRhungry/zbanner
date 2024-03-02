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
#include "../output/output.h"
#include "../proto/proto-preprocess.h"
#include "../stack/stack-queue.h"
#include "../probe-modules/probe-modules.h"


#define SCAN_MODULE_DEFAULT_DEDUP_TYPE     0

/***************************************************************************
 * * callback functions for Init
****************************************************************************/

/**
 * Do some initialization here if you have to.
 * !Must be implemented.
 * @param xconf main conf of xtate, use `void` to avoiding x-ref.
 * @return false for initing failed and exit process.
*/
typedef int (*scan_modules_global_init)(const void *xconf);

/***************************************************************************
 * * callback functions for Transmit
****************************************************************************/

struct ScanTarget {
    ipaddress ip_them;
    ipaddress ip_me;
    unsigned port_them;
    unsigned port_me;
    unsigned proto;
    unsigned index;
};

/**
 * Happens in Tx Thread.
 * Do the first packet transmitting for every target.
 * 
 * !Must be implemented.
 * !Must be thread safe.
 * 
 * @param entropy a rand seed (generated or user-specified).
 * @param target info of target.
 * @param px packet buffer to transmit. (Length is PKT_BUF_LEN)
 * @param len length of packet data.
 * @return true if need to transmit one more packet.
*/
typedef int (*scan_modules_transmit)(
    uint64_t entropy,
    struct ScanTarget *target,
    unsigned char *px, size_t *len);

/***************************************************************************
 * * callback functions for Receive
****************************************************************************/

struct Received {
    struct PreprocessedInfo parsed;
    const unsigned char *packet;
    unsigned length;
    unsigned is_myip;
    unsigned is_myport;
    unsigned secs;
    unsigned usecs;
};

struct PreHandle {
    unsigned go_record:1; /*proceed to record or stop*/
    unsigned go_dedup:1; /*proceed to dedup or stop*/
    unsigned no_dedup:1; /*go on with(out) deduping*/
    ipaddress dedup_ip_them;
    unsigned dedup_port_them;
    ipaddress dedup_ip_me;
    unsigned dedup_port_me;
    unsigned dedup_type;
};

/**
 * !First Step Happens in Rx Thread.
 * Do following things for a received packet:
 *  1. Record or stop.
 *  2. Is and How to dedup or stop.
 * 
 * !Must be implemented.
 * !Must be thread safe.
 * 
 * @param entropy a rand seed (generated or user-specified).
 * @param recved info of received packet.
 * @param pre some preHandle results.
*/
typedef void (*scan_modules_validate)(
    uint64_t entropy,
    struct Received *recved,
    struct PreHandle *pre);

/**
 * !Second Step Happens in Rx Thread.
 * Do following things for a received packet:
 *  1. Is and How to output a result.
 *  2. How and What packet to response.
 * 
 * !Must be implemented.
 * !Must be thread safe.
 * 
 * @param entropy a rand seed (generated or user-specified).
 * @param recved info of received packet.
 * @param item some outputting results.
 * @param stack packet buffer queue stack for preparing transmitting.
*/
typedef void (*scan_modules_handle)(
    uint64_t entropy,
    struct Received *recved,
    struct OutputItem *item,
    struct stack_t *stack);


/***************************************************************************
 * * callback functions for Close
****************************************************************************/

/**
 * It happens before normal exit in mainscan function.
*/
typedef void (*scan_modules_close)();


struct ScanModule
{
    const char                                 *name;
    const char                                 *desc;
    const enum ProbeType                        required_probe_type; /*set zero if not using probe*/
    /**
     * Set BPF filter for better performance while using pcap to transmit.
     * But We need to write correct valicate callback func for other transmit mode
     */
    const char                                 *bpf_filter; 
    /*Some ScanModule may need arguments*/
    char                                       *args;
    struct ProbeModule                         *probe;
    /*for init*/
    scan_modules_global_init                    global_init_cb;
    /*for transmit*/
    scan_modules_transmit                       transmit_cb;
    /*for receive*/
    scan_modules_validate                       validate_cb;
    scan_modules_handle                         handle_cb;
    /*for close*/
    scan_modules_close                          close_cb;
};

struct ScanModule *get_scan_module_by_name(const char *name);

void list_all_scan_modules();

/************************************************************************
Some useful implemented interfaces
************************************************************************/

/*implemented `scan_modules_xxx_init`*/
int scan_init_nothing(const void *params);

/*implemented `scan_modules_close`*/
void scan_close_nothing();

#endif
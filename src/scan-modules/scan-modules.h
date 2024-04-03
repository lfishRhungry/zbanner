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

#include "../globals.h"
#include "../util-misc/configer.h"
#include "../util-misc/cross.h"
#include "../output-modules/output-modules.h"
#include "../stack/stack-queue.h"
#include "../massip/massip-addr.h"
#include "../timeout/fast-timeout.h"
#include "../proto/proto-preprocess.h"
#include "../probe-modules/probe-modules.h"

struct Xconf;

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
typedef bool (*scan_modules_global_init)(const struct Xconf *xconf);

/***************************************************************************
 * * callback functions for Transmit
****************************************************************************/

struct ScanTarget {
    ipaddress ip_them;
    ipaddress ip_me;
    unsigned  port_them;
    unsigned  port_me;
    unsigned  proto;
    unsigned  index; /*use in tx thread for multi packets per target in ScanModule*/
};

struct ScanTimeoutEvent {
    ipaddress ip_them;
    ipaddress ip_me;
    unsigned  port_them;
    unsigned  port_me;
    unsigned  dedup_type;
    unsigned  need_timeout;
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
 * @param event fill the info of timeout event to it.
 * @param px packet buffer to transmit. (Length is PKT_BUF_LEN)
 * @param len length of packet data.
 * @return true if need to transmit one more packet.
*/
typedef bool (*scan_modules_transmit)(
    uint64_t entropy,
    struct ScanTarget *target,
    struct ScanTimeoutEvent *event,
    unsigned char *px, size_t *len);

/***************************************************************************
 * * callback functions for Receive
****************************************************************************/

struct Received {
    struct PreprocessedInfo parsed;
    unsigned char *packet;
    unsigned length;
    unsigned is_myip;
    unsigned is_myport;
    unsigned secs;
    unsigned usecs;
};

struct PreHandle {
    unsigned  go_record:1; /*proceed to record or stop*/
    unsigned  go_dedup:1; /*proceed to dedup or stop*/
    unsigned  no_dedup:1; /*go on with(out) deduping*/
    ipaddress dedup_ip_them;
    unsigned  dedup_port_them;
    ipaddress dedup_ip_me;
    unsigned  dedup_port_me;
    unsigned  dedup_type;
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
 * @param th_idx the index of receive handler thread.
 * @param entropy a rand seed (generated or user-specified).
 * @param recved info of received packet.
 * @param item some outputting results.
 * @param stack packet buffer queue stack for preparing transmitting.
 * @param handler handler of fast-timeout or NULL if not in use fast-timeout.
*/
typedef void (*scan_modules_handle)(
    unsigned th_idx,
    uint64_t entropy,
    struct Received *recved,
    struct OutputItem *item,
    struct stack_t *stack,
    struct FHandler *handler);

/**
 * !Happens in Rx Thread.
 * Handle fast-timeout event if we use fast-timeout.
 * This func will be called only if we use fast-timeout.
 * 
 * !Must be implemented.
 * !Must be thread safe.
 * 
 * @param entropy a rand seed (generated or user-specified).
 * @param event timeout event;
 * @param item some outputting results.
 * @param stack packet buffer queue stack for preparing transmitting.
 * @param handler handler of fast-timeout or NULL if not in use fast-timeout.
*/
typedef void (*scan_modules_timeout)(
    uint64_t entropy,
    struct ScanTimeoutEvent *event,
    struct OutputItem *item,
    struct stack_t *stack,
    struct FHandler *handler);

typedef void (*scan_modules_poll)();


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
    const enum ProbeType                        required_probe_type; /*set zero if not using probe*/
    const unsigned                              support_timeout;
    const char                                 *bpf_filter;          /*just for pcap*/
    struct ConfigParam                     *params;
    struct ProbeModule                         *probe;
    const char                                 *desc;

    /*for init*/
    scan_modules_global_init                    global_init_cb;
    /*for transmit*/
    scan_modules_transmit                       transmit_cb;
    /*for receive*/
    scan_modules_validate                       validate_cb;
    scan_modules_handle                         handle_cb;
    /*for timeout*/
    scan_modules_timeout                        timeout_cb;
    /*for polling*/
    scan_modules_poll                           poll_cb;
    /*for close*/
    scan_modules_close                          close_cb;
};

struct ScanModule *get_scan_module_by_name(const char *name);

void list_all_scan_modules();

/************************************************************************
Some useful implemented interfaces
************************************************************************/

/*implemented `scan_modules_xxx_init`*/
bool scan_global_init_nothing(const struct Xconf *params);

/*implemented `scan_modules_poll`*/
void scan_poll_nothing();

/*implemented `scan_modules_close`*/
void scan_close_nothing();

void scan_no_timeout(
    uint64_t entropy,
    struct ScanTimeoutEvent *event,
    struct OutputItem *item,
    struct stack_t *stack,
    struct FHandler *handler);

#endif
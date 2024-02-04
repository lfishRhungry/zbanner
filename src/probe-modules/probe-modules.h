#include <stdlib.h>

#include "../massip/massip-addr.h"

#ifndef PROBE_MODULES_H
#define PROBE_MODULES_H

#define PROBE_PAYLOAD_MAX_LEN 1460
#define PROBE_REPORT_MAX_LEN 1460

enum ProbeType {
    ProbeType_TCP   = 1,
    ProbeType_UDP   = 1<<1,
    ProbeType_SCTP  = 1<<2,
    ProbeType_MAX   = 1<<3,
};


/**
 * @return FALSE to exit process if init failed
*/
typedef int (*probe_modules_global_init)();

/**
 * Happens in Rx Thread
 * !Must be thread safe.
 * @return FALSE to exit process if init failed
*/
typedef int (*probe_modules_rxthread_init)();

/**
 * Happens in Tx Thread
 * !Must be thread safe.
 * @return FALSE to exit process if init failed
*/
typedef int (*probe_modules_txthread_init)();

/**
 * Happens in Tx Thread or Rx Thread for different ScanModules.
 * 
 * Make correspond payload data for a target.
 * We could embed a cookie to payload for response validating.
 * 
 * !Must be implemented.
 * !Must be thread safe.
 * 
 * @param ip_them target ip
 * @param port_them target port
 * @param ip_me source ip
 * @param port_me source port
 * @param cookie unique identification for this target
 * @param payload_buf buffer to fill with payload data
 * @param buf_len length of buffer
 * @return length of payload data
*/
typedef size_t
(*probe_modules_make_payload)(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned cookie,
    unsigned char *payload_buf,
    size_t buf_length);

/**
 * Happens both in Tx and Rx thread.
 * 
 * Use this interface for possible copies reducing or just wrap
 * `probe_modules_make_payload`.
 * The length of payload is independent of cookie.
 * 
 * !Must be implemented for ProbeType_TCP.
 * !Must be thread safe.
 * 
 * @param ip_them target ip
 * @param port_them target port
 * @param ip_me source ip
 * @param port_me source port
 * @param cookie unique identification for this target
 * @return length of payload data
*/
typedef size_t
(*probe_modules_get_payload_length)(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me);

/**
 * Happens in Rx Thread
 * 
 * Validate whether the response is for us(because of stateless).
 * This is useful when ScanModule cannot validate through the
 * packet attributes.
 * 
 * !Must be implemented for ProbeType_UDP.
 * !Must be thread safe.
 * 
 * @param ip_them target ip
 * @param port_them target port
 * @param ip_me source ip
 * @param port_me source port
 * @param cookie unique identification for this target
 * @param px response data
 * @param sizeof_px len of reponse
 * @return TRUE if the response is for us.
*/
typedef int
(*probe_modules_validate_response)(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned cookie,
    const unsigned char *px, unsigned sizeof_px
);

/**
 * Happens in Rx Thread,
 * Decide the classification and report of the reponse
 * and whether it is successed.
 * 
 * !Must be implemented.
 * !Must be thread safe.
 * 
 * @param ip_them target ip
 * @param port_them target port
 * @param ip_me source ip
 * @param port_me source port
 * @param px response data
 * @param sizeof_px len of reponse
 * @param successed Is this packet considered success.
 * @param classification Packet classification string.
 * @param cls_length Length of classification string buffer.
 * @param report Report string.
 * @param rpt_length Length of report string buffer.
*/
typedef void
(*probe_modules_handle_response)(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    const unsigned char *px, unsigned sizeof_px,
    unsigned *successed,
    char *classification, unsigned cls_length,
    char *report, unsigned rpt_length
);

/**
 * It happens before normal exit in mainscan function.
*/
typedef int (*probe_modules_close)();

struct ProbeModule
{
    const char                        *name;
    const unsigned                     type;
    const char                        *desc;
    char                              *args;
    /*for init*/
    probe_modules_global_init          global_init_cb;
    probe_modules_rxthread_init        rx_thread_init_cb;
    probe_modules_txthread_init        tx_thread_init_cb;
    /*for payload and response*/
    probe_modules_make_payload         make_payload_cb;
    probe_modules_get_payload_length   get_payload_length_cb;
    probe_modules_validate_response    validate_response_cb;
    probe_modules_handle_response      handle_response_cb;
    /*for close*/
    probe_modules_close                close_cb;
};

struct ProbeModule *get_probe_module_by_name(const char *name);

void list_all_probe_modules();

#endif
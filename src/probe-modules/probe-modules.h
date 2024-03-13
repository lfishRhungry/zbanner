#include <stdlib.h>

#include "../massip/massip-addr.h"
#include "../output/output.h"
#include "../param-configer.h"
#include "../util/unusedparm.h"

#ifndef PROBE_MODULES_H
#define PROBE_MODULES_H

#define PROBE_PAYLOAD_MAX_LEN 2048


/**
 * !Must be implemented.
 * @param xconf main conf of xtate, use `void` to avoiding x-ref.
 * @return FALSE to exit process if init failed
*/
typedef int (*probe_modules_global_init)(const void *xconf);

struct ProbeTarget {
    ipaddress ip_them;
    ipaddress ip_me;
    unsigned  port_them;
    unsigned  port_me;
    unsigned  cookie;
    unsigned  index; /*use for identifying of multi probes per target in ProbeModule*/
};

/**
 * Happens in Tx Thread or Rx Thread for different ScanModules.
 * 
 * Make correspond payload data for a target.
 * We could embed a cookie to payload for response validating.
 * 
 * 
 * !Must be implemented.
 * !Must be thread safe.
 * 
 * @param target info of a target
 * @param payload_buf buffer to fill with payload. (Length is PROBE_PAYLOAD_MAX_LEN)
 * @return paylaod length.
*/
typedef size_t
(*probe_modules_make_payload)(
    struct ProbeTarget *target,
    unsigned char *payload_buf);

/**
 * Happens in Tx Thread or Rx Thread for different ScanModules.
 * 
 * !Must be implemented for ProbeType_TCP.
 * !Must be thread safe.
 * 
 * @param target info of a target
 * @return length of payload data
*/
typedef size_t
(*probe_modules_get_payload_length)(struct ProbeTarget *target);

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
 * @param target info of a target
 * @param px response data
 * @param sizeof_px len of reponse
 * @return TRUE if the response is for us.
*/
typedef int
(*probe_modules_validate_response)(
    struct ProbeTarget *target,
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
 * @param target info of a target
 * @param px response data
 * @param sizeof_px len of reponse (it can be 0 for no response while timeouted)
 * @param item to define output content.
 * @return true for starting multi-probe in Multi_AfterHandle mode.
*/
typedef int
(*probe_modules_handle_response)(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item);

/**
 * It happens before normal exit in mainscan function.
 * !Must be implemented.
*/
typedef void (*probe_modules_close)();

/*a probe belongs to one type*/
enum ProbeType {
    ProbeType_NULL = 0,
    ProbeType_TCP,
    ProbeType_UDP,
};

enum MultiMode {
    Multi_Null = 0,
    Multi_Direct,         /*send multi_num probes(diff in index) when first connect.*/
    Multi_IfOpen,         /*send multi_num probes(diff in index) if port is open. !Just for TCP*/
    Multi_AfterHandle,    /*send multi-num probes(diff in index) after first handled.*/
    Multi_DynamicNext,    /*send a specified probe(with index+1) after every time handled*/
};

struct ProbeModule
{
    const char                                 *name;
    const enum ProbeType                        type;
    enum MultiMode                              multi_mode;
    unsigned                                    multi_num; /*useless for Multi_DynamicNext*/
    const char                                 *desc;
    struct ConfigParameter                     *params;

    /*for init*/
    probe_modules_global_init                   global_init_cb;
    /*for payload*/
    probe_modules_make_payload                  make_payload_cb;
    probe_modules_get_payload_length            get_payload_length_cb;
    /*for response*/
    probe_modules_validate_response             validate_response_cb;
    probe_modules_handle_response               handle_response_cb;
    /*for close*/
    probe_modules_close                         close_cb;
};

struct ProbeModule *get_probe_module_by_name(const char *name);

const char *
get_probe_type_name(const enum ProbeType type);

void list_all_probe_modules();

/************************************************************************
Some useful implemented interfaces
************************************************************************/

/*implemented `probe_modules_xxx_init`*/
int probe_init_nothing(const void *params);

size_t
probe_make_no_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf);

/*implemented `probe_modules_get_payload_length`*/
size_t
probe_no_payload_length(struct ProbeTarget *target);

/*implemented `probe_modules_handle_reponse`*/
int
probe_report_nothing(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item);

/*implemented `probe_modules_handle_reponse`*/
int
probe_just_report_banner(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item);

/*implemented `probe_modules_close`*/
void probe_close_nothing();

#endif
#ifndef PROBE_MODULES_H
#define PROBE_MODULES_H

#include <stdlib.h>

#include "../massip/massip-addr.h"
#include "../output-modules/output-modules.h"
#include "../param-configer.h"
#include "../util/unusedparm.h"
#include "../proto/proto-datapass.h"

struct Xconf;

#define PROBE_PAYLOAD_MAX_LEN 2048

/**
 * !Must be implemented.
 * 
 * @param xconf main conf of xtate, use `void` to avoiding x-ref.
 * @return FALSE to exit process if init failed
*/
typedef unsigned (*probe_modules_global_init)(const struct Xconf *xconf);

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
 * Make correspond hello payload data for a target.
 * We could embed a cookie to payload for response validating in ProbeType_UDP.
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
 * !Must check index range in multi-probe
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
typedef unsigned
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
typedef unsigned
(*probe_modules_handle_response)(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item);

struct ProbeState {
    unsigned  state;
    void     *data; /*diff from probes, managed by probe self*/
};

/**
 * Do init for a connection
 * 
 * !Must be implemented for ProbeType STATE
 * !Must be thread safe.
 * 
 * @param state probe state
 * @param target target info
*/
typedef void
(*probe_modules_conn_init)(struct ProbeState *state, struct ProbeTarget *target);

/**
 * Make correspond hello payload data for a target.
 * 
 * 
 * !Must be implemented for ProbeType STATE
 * !Must be thread safe.
 * 
 * @param state probe state
 * @param target info of a target
 * @param payload_buf buffer to fill with payload. (Length is PROBE_PAYLOAD_MAX_LEN)
 * @return paylaod length.
*/
typedef void
(*probe_modules_make_hello)(
    struct DataPass *pass,
    struct ProbeState *state,
    struct ProbeTarget *target);

/**
 * 
 * Interacting with target after receive data.
 * 
 * !Must be implemented for ProbeType_STATE.
 * !Must be thread safe.
 * 
 * @param pass   used for pass data(for sending) to down-layer protocol.
 * @param state  state that probe setted.
 * @param out    used for outputing results.
 * @param target info of a target
 * @param px response data
 * @param sizeof_px len of reponse
 * @return TRUE if the response is for us.
*/
typedef void
(*probe_modules_parse_response)(
    struct DataPass *pass,
    struct ProbeState *state,
    struct Output *out,
    struct ProbeTarget *target,
    const unsigned char *px,
    unsigned sizeof_px);

/**
 * Do init for a connection
 * 
 * !Must be implemented for ProbeType STATE
 * !Must be thread safe.
 * 
 * @param state probe state
 * @param target target info
*/
typedef void
(*probe_modules_conn_close)(struct ProbeState *state, struct ProbeTarget *target);

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
    ProbeType_STATE,
};

enum MultiMode {
    Multi_Null = 0,
    Multi_Direct,         /*send multi_num probes(diff in index) when first connect.*/
    Multi_IfOpen,         /*send multi_num probes(diff in index) if port is open. !Just for TCP*/
    Multi_AfterHandle,    /*send multi-num probes(diff in index) after first handled.*/
    Multi_DynamicNext,    /*send a specified probe(with index+1) after every time handled*/
};

enum HelloType {
    Wait_Hello         = 0,    /* wait for a fixed time before sending hello*/
    Hello_Close        = 0x01, /* send FIN after the static Hello is sent*/
    Nowait_Hello       = 0x02, /* send our hello immediately, don't wait for their hello */
};

struct ProbeModule
{
    const char                                 *name;
    const enum ProbeType                        type;
    const enum MultiMode                        multi_mode;
    const unsigned                              multi_num;   /*useless for Multi_DynamicNext*/
    unsigned int                                hello_wait;  /*just for statefull scan*/
    const char                                 *desc;
    struct ConfigParameter                     *params;

    /*for init*/
    probe_modules_global_init                   global_init_cb;
    /*for stateless payload*/
    probe_modules_make_payload                  make_payload_cb;
    probe_modules_get_payload_length            get_payload_length_cb;
    /*for stateless response*/
    probe_modules_validate_response             validate_response_cb;
    probe_modules_handle_response               handle_response_cb;
    /*for stateful process*/
    probe_modules_conn_init                     conn_init_cb;
    probe_modules_make_hello                    make_hello_cb;
    probe_modules_parse_response                parse_response_cb;
    probe_modules_conn_close                    conn_close_cb;
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
unsigned probe_global_init_nothing(const struct Xconf *xconf);

size_t
probe_make_no_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf);

/*implemented `probe_modules_get_payload_length`*/
size_t
probe_no_payload_length(struct ProbeTarget *target);

/*implemented `probe_modules_handle_reponse`*/
unsigned
probe_report_nothing(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item);

/*implemented `probe_modules_handle_reponse`*/
unsigned
probe_just_report_banner(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item);

/*implemented `probe_modules_close`*/
void probe_close_nothing();

void probe_conn_init_nothing(struct ProbeState *state, struct ProbeTarget *target);

void probe_conn_close_nothing(struct ProbeState *state, struct ProbeTarget *target);

#endif
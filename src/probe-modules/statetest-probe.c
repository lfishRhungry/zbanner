#include <string.h>
#include <stdio.h>

#include "probe-modules.h"
#include "../util/safe-string.h"
#include "../output/output.h"

#define GETREQUEST_PAYLOAD "GET / HTTP/1.0\r\n\r\n"

/*for internal x-ref*/
extern struct ProbeModule StateTestProbe;

static void
getrequest_make_hello(
    struct DataPass *pass,
    struct ProbeState *state,
    struct ProbeTarget *target)
{
    /*static data*/
    pass->payload = (unsigned char *)GETREQUEST_PAYLOAD;
    pass->len     = strlen(GETREQUEST_PAYLOAD);
}

static void
getrequest_parse_response(
    struct DataPass *pass,
    struct ProbeState *state,
    struct Output *out,
    struct ProbeTarget *target,
    const unsigned char *px,
    unsigned sizeof_px)
{
    if (state->state) return;
    state->state = 1;

    pass->close = 1;

    struct OutputItem item = {
        .level = Output_SUCCESS,
        .ip_them = target->ip_them,
        .ip_me = target->ip_me,
        .port_them = target->port_them,
        .port_me = target->port_me,
    };

    safe_strcpy(item.classification, OUTPUT_CLS_LEN, "banner");
    safe_strcpy(item.reason, OUTPUT_RSN_LEN, "responsed");
    normalize_string(px, sizeof_px, item.report, OUTPUT_RPT_LEN);

    output_result(out, &item);
}

struct ProbeModule StateTestProbe = {
    .name       = "statetest",
    .type       = ProbeType_STATE,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .hello_wait = 3,
    .params     = NULL,
    .desc =
        "GetRequest Probe sends target port a simple HTTP Get request:\n"
        "    `GET / HTTP/1.0\\r\\n\\r\\n`\n"
        "It could get a simple result from http server fastly.",
    .global_init_cb                    = &probe_init_nothing,
    .make_payload_cb                   = NULL,
    .get_payload_length_cb             = NULL,
    .validate_response_cb              = NULL,
    .handle_response_cb                = NULL,
    .conn_init_cb                      = &probe_conn_init_nothing,
    .make_hello_cb                     = &getrequest_make_hello,
    .parse_response_cb                 = &getrequest_parse_response,
    .conn_close_cb                     = &probe_conn_close_nothing,
    .close_cb                          = &probe_close_nothing,
};
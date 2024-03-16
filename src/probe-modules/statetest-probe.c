#include <string.h>
#include <stdio.h>

#include "probe-modules.h"
#include "../util/safe-string.h"
#include "../stack/stack-tcp-core.h"
#include "../output/output.h"

#define GETREQUEST_PAYLOAD "GET / HTTP/1.0\r\n\r\n"

/*for internal x-ref*/
extern struct ProbeModule StateTestProbe;

static size_t
getrequest_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, GETREQUEST_PAYLOAD, strlen(GETREQUEST_PAYLOAD));
    return strlen(GETREQUEST_PAYLOAD);
}

static void
getrequest_parse_response(
    stack_handle_t *socket,
    struct ProbeState *state,
    struct Output *out,
    struct ProbeTarget *target,
    const unsigned char *px,
    unsigned sizeof_px)
{
    if (state->state) return;
    state->state = 1;

    tcpapi_close(socket);

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
    .hello      = Nowait_Hello,
    .params     = NULL,
    .desc =
        "GetRequest Probe sends target port a simple HTTP Get request:\n"
        "    `GET / HTTP/1.0\\r\\n\\r\\n`\n"
        "It could get a simple result from http server fastly.",
    .global_init_cb                    = &probe_init_nothing,
    .make_payload_cb                   = &getrequest_make_payload,
    .get_payload_length_cb             = NULL,
    .validate_response_cb              = NULL,
    .handle_response_cb                = NULL,
    .parse_response_cb                 = &getrequest_parse_response,
    .close_cb                          = &probe_close_nothing,
};
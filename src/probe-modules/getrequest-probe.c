#include <string.h>

#include "probe-modules.h"

#define GETREQUEST_PAYLOAD "GET / HTTP/1.0\r\n\r\n"

/*for internal x-ref*/
extern struct ProbeModule GetRequestProbe;

static size_t
getrequest_make_payload(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned cookie, unsigned idx,
    unsigned char *payload_buf,
    size_t buf_length)
{
    memcpy(payload_buf, GETREQUEST_PAYLOAD, strlen(GETREQUEST_PAYLOAD));
    return strlen(GETREQUEST_PAYLOAD);
}

static size_t
getrequest_get_payload_length(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned cookie, unsigned idx)
{
    return strlen(GETREQUEST_PAYLOAD);
}

struct ProbeModule GetRequestProbe = {
    .name      = "getrequest",
    .type      = ProbeType_TCP,
    .probe_num = 1,
    .desc =
        "GetRequest Probe sends target port a simple HTTP Get request:\n"
        "    `GET / HTTP/1.0\\r\\n\\r\\n`\n"
        "It could get a simple result from http server fastly.\n",
    .global_init_cb                    = &probe_init_nothing,
    .make_payload_cb                   = &getrequest_make_payload,
    .get_payload_length_cb             = &getrequest_get_payload_length,
    .validate_response_cb              = NULL,
    .handle_response_cb                = &probe_just_report_banner,
    .close_cb                          = &probe_close_nothing,
};
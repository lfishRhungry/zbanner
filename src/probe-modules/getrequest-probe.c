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

struct ProbeModule GetRequestProbe = {
    .name = "getrequest",
    .type = ProbeType_TCP,
    .desc =
        "GetRequest Probe sends target port a simple HTTP Get request:\n"
        "    `GET / HTTP/1.0\\r\\n\\r\\n`\n"
        "It could get a simple result from http server fastly.\n",
    .global_init_cb = NULL,
    .rx_thread_init_cb = NULL,
    .tx_thread_init_cb = NULL,
    .make_payload_cb = &getrequest_make_payload,
    .validate_response_cb = NULL,
    .handle_response_cb = &just_report_banner,
    .close_cb = NULL
};
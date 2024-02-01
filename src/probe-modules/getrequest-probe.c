#include "../xconf.h"
#include "null-probe.h"
#include "getrequest-probe.h"

struct ProbeModule GetRequestProbe = {
    .name = "getrequest",
    .type = Tcp_Probe,
    .help_text =
        "GetRequest Probe sends target port a simple HTTP Get request:\n"
        "    `GET / HTTP/1.0\\r\\n\\r\\n`\n"
        "It could get result from http server fastly.\n",
    .global_init_cb = NULL,
    .thread_init_cb = NULL,
    .make_payload_cb = &getrequest_make_payload,
    .get_payload_length_cb = &getrequest_get_payload_length,
    .get_report_banner_cb = &just_report_banner,
    .close_cb = NULL
};

size_t getrequest_make_payload(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me,
    unsigned char *payload_buf, size_t buf_len)
{
    memcpy(payload_buf, GETREQUEST_PAYLOAD, strlen(GETREQUEST_PAYLOAD));
    return strlen(GETREQUEST_PAYLOAD);
}

size_t getrequest_get_payload_length(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me)
{
    return strlen(GETREQUEST_PAYLOAD);
}

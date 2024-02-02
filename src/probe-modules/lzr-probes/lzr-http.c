#include <string.h>

#include "lzr-http.h"
#include "../../util/mas-safefunc.h"

static char lzr_http_fmt[] = "GET / HTTP/1.1\r\n"
    "Host: %s:%u\r\n"
    "User-Agent: Mozilla/5.0 "XTATE_WITH_VERSION"\r\n"
    "Accept: */*\r\n"
    "Accept-Encoding: gzip\r\n"
    "\r\n";

static size_t
lzr_http_make_payload(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned cookie,
    unsigned char *payload_buf,
    size_t buf_length)
{
    return snprintf((char *)payload_buf, buf_length, lzr_http_fmt,
        ipaddress_fmt(ip_them).string, port_them);
}

static void
lzr_http_handle_reponse(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    const unsigned char *px, unsigned sizeof_px,
    unsigned *successed,
    char *classification, unsigned cls_length,
    char *report, unsigned rpt_length)
{
    if (!strstr((const char *)px, "HTTPS")
        &&
        (strstr((const char *)px, "HTTP")
            || strstr((const char *)px, "html")
            || strstr((const char *)px, "HTML")
            || strstr((const char *)px, "<h1>"))) {
        safe_strcpy(report, rpt_length, "http");
        *successed = 1;
    } else {
        *successed = 0;
    }
    /*Too many string copies if we set classification while LzrProbe*/
}

struct ProbeModule LzrHttpProbe = {
    .name = "lzr-http",
    .type = ProbeType_TCP,
    .desc =
        "LzrHttp Probe sends an HTTP GET request and identifies HTTP service.\n",
    .global_init_cb = NULL,
    .rx_thread_init_cb = NULL,
    .tx_thread_init_cb = NULL,
    .make_payload_cb = &lzr_http_make_payload,
    .validate_response_cb = NULL,
    .handle_response_cb = &lzr_http_handle_reponse,
    .close_cb = NULL
};
#include <string.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util/mas-safefunc.h"

/*for internal x-ref*/
extern struct ProbeModule LzrHttpProbe;

static char lzr_http_fmt_ipv4[] = "GET / HTTP/1.1\r\n"
    "Host: %s:%u\r\n"
    "User-Agent: Mozilla/5.0 "XTATE_WITH_VERSION"\r\n"
    "Accept: */*\r\n"
    "Accept-Encoding: gzip\r\n"
    "\r\n";

static char lzr_http_fmt_ipv6[] = "GET / HTTP/1.1\r\n"
    "Host: [%s:%u]\r\n"
    "User-Agent: Mozilla/5.0 "XTATE_WITH_VERSION"\r\n"
    "Accept: */*\r\n"
    "Accept-Encoding: gzip\r\n"
    "\r\n";

static size_t
lzr_http_make_payload(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned cookie, unsigned idx,
    unsigned char *payload_buf,
    size_t buf_length)
{
    if (ip_them.version==4)
        return snprintf((char *)payload_buf, buf_length, lzr_http_fmt_ipv4,
            ipaddress_fmt(ip_them).string, port_them);
    else
        return snprintf((char *)payload_buf, buf_length, lzr_http_fmt_ipv6,
            ipaddress_fmt(ip_them).string, port_them);
}

static size_t
lzr_http_get_payload_length(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned cookie, unsigned idx)
{
    unsigned char tmp_str[200];
    return lzr_http_make_payload(ip_them, port_them,
        ip_me, port_me, cookie, idx, tmp_str, 200);
}

static void
lzr_http_handle_reponse(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned idx,
    const unsigned char *px, unsigned sizeof_px,
    char *report, unsigned rpt_length)
{
    if (!safe_memmem(px, sizeof_px, "HTTPS", strlen("HTTPS"))
        &&
        (safe_memmem(px, sizeof_px, "HTTP", strlen("HTTP"))
            || safe_memmem(px, sizeof_px, "html", strlen("html"))
            || safe_memmem(px, sizeof_px, "HTML", strlen("HTML"))
            || safe_memmem(px, sizeof_px, "<h1>", strlen("<h1>")))) {
        safe_strcpy(report, rpt_length, "http");
    }
}

struct ProbeModule LzrHttpProbe = {
    .name = "lzr-http",
    .type = ProbeType_TCP,
    .desc =
        "LzrHttp Probe sends an HTTP GET request and identifies HTTP service.\n",
    .global_init_cb = &probe_init_nothing,
    .rx_thread_init_cb = &probe_init_nothing,
    .tx_thread_init_cb = &probe_init_nothing,
    .make_payload_cb = &lzr_http_make_payload,
    .get_payload_length_cb = &lzr_http_get_payload_length,
    .validate_response_cb = NULL,
    .handle_response_cb = &lzr_http_handle_reponse,
    .close_cb = &probe_close_nothing,
};
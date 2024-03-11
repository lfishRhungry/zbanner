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
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    if (target->ip_them.version==4)
        return snprintf((char *)payload_buf,
            PROBE_PAYLOAD_MAX_LEN, lzr_http_fmt_ipv4,
            ipaddress_fmt(target->ip_them).string, target->port_them);
    else
        return snprintf((char *)payload_buf,
            PROBE_PAYLOAD_MAX_LEN, lzr_http_fmt_ipv6,
            ipaddress_fmt(target->ip_them).string, target->port_them);
}

static size_t
lzr_http_get_payload_length(struct ProbeTarget *target)
{
    unsigned char tmp_str[PROBE_PAYLOAD_MAX_LEN];
    return lzr_http_make_payload(target, tmp_str);
}

static int
lzr_http_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    char *report)
{
    if (sizeof_px==0)
        return 0;
    
    if (!safe_memmem(px, sizeof_px, "HTTPS", strlen("HTTPS"))
        &&
        (safe_memmem(px, sizeof_px, "HTTP", strlen("HTTP"))
            || safe_memmem(px, sizeof_px, "html", strlen("html"))
            || safe_memmem(px, sizeof_px, "HTML", strlen("HTML"))
            || safe_memmem(px, sizeof_px, "<h1>", strlen("<h1>")))) {
        safe_strcpy(report, PROBE_REPORT_MAX_LEN, "http");
    }

    return 0;
}

struct ProbeModule LzrHttpProbe = {
    .name       = "lzr-http",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .desc =
        "LzrHttp Probe sends an HTTP GET request and identifies HTTP service.\n",
    .global_init_cb                          = &probe_init_nothing,
    .make_payload_cb                         = &lzr_http_make_payload,
    .get_payload_length_cb                   = &lzr_http_get_payload_length,
    .validate_response_cb                    = NULL,
    .handle_response_cb                      = &lzr_http_handle_reponse,
    .close_cb                                = &probe_close_nothing,
};
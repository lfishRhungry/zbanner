#include <string.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrHttpProbe;

static char lzr_http_fmt_ipv4[] = "GET / HTTP/1.1\r\n"
    "Host: %s\r\n"
    "User-Agent: Mozilla/5.0 "XTATE_WITH_VERSION"\r\n"
    "Accept: */*\r\n"
    "Accept-Encoding: gzip\r\n"
    "\r\n";

static char lzr_http_fmt_ipv6[] = "GET / HTTP/1.1\r\n"
    "Host: [%s]\r\n"
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
            PM_PAYLOAD_SIZE, lzr_http_fmt_ipv4,
            ipaddress_fmt(target->ip_them).string);
    else
        return snprintf((char *)payload_buf,
            PM_PAYLOAD_SIZE, lzr_http_fmt_ipv6,
            ipaddress_fmt(target->ip_them).string);
}

static size_t
lzr_http_get_payload_length(struct ProbeTarget *target)
{
    unsigned char tmp_str[PM_PAYLOAD_SIZE];
    return lzr_http_make_payload(target, tmp_str);
}

static unsigned
lzr_http_handle_reponse(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    OutItem *item)
{

    if (!safe_memmem(px, sizeof_px, "HTTPS", strlen("HTTPS"))
        &&
        (safe_memmem(px, sizeof_px, "HTTP", strlen("HTTP"))
            || safe_memmem(px, sizeof_px, "html", strlen("html"))
            || safe_memmem(px, sizeof_px, "HTML", strlen("HTML"))
            || safe_memmem(px, sizeof_px, "<h1>", strlen("<h1>")))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "http");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not http");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_http_handle_timeout(struct ProbeTarget *target, OutItem *item)
{
    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not http");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

struct ProbeModule LzrHttpProbe = {
    .name       = "lzr-http",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrHttp Probe sends an HTTP GET request and identifies HTTP service.",
    .init_cb                                 = &probe_init_nothing,
    .make_payload_cb                         = &lzr_http_make_payload,
    .get_payload_length_cb                   = &lzr_http_get_payload_length,
    .handle_response_cb                      = &lzr_http_handle_reponse,
    .handle_timeout_cb                       = &lzr_http_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
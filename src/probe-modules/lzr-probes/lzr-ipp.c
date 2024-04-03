#include <string.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrIppProbe;

static char lzr_ipp_fmt_ipv4[] = "POST /ipp HTTP/1.1\r\n"
    "Host: %s:%u\r\n"
    "User-Agent: Mozilla/5.0 "XTATE_WITH_VERSION"\r\n"
    "Accept: */*\r\n"
    "Content-Type: application/ipp\r\n"
    "Accept-Encoding: gzip\r\n"
    "\r\n";

static char lzr_ipp_fmt_ipv6[] = "POST /ipp HTTP/1.1\r\n"
    "Host: [%s:%u]\r\n"
    "User-Agent: Mozilla/5.0 "XTATE_WITH_VERSION"\r\n"
    "Accept: */*\r\n"
    "Content-Type: application/ipp\r\n"
    "Accept-Encoding: gzip\r\n"
    "\r\n";

static size_t
lzr_ipp_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    if (target->ip_them.version==4)
        return snprintf((char *)payload_buf,
            PROBE_PAYLOAD_MAX_LEN, lzr_ipp_fmt_ipv4,
            ipaddress_fmt(target->ip_them).string, target->port_them);
    else
        return snprintf((char *)payload_buf,
            PROBE_PAYLOAD_MAX_LEN, lzr_ipp_fmt_ipv6,
            ipaddress_fmt(target->ip_them).string, target->port_them);
}

static size_t
lzr_ipp_get_payload_length(struct ProbeTarget *target)
{
    unsigned char tmp_str[PROBE_PAYLOAD_MAX_LEN];
    return lzr_ipp_make_payload(target, tmp_str);
}

static unsigned
lzr_ipp_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not ipp");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }

    if (safe_memmem(px, sizeof_px, "ipp", strlen("ipp"))
        && safe_memmem(px, sizeof_px, "200 OK", strlen("200 OK"))) {
        if (safe_memmem(px, sizeof_px, "attributes-charset", strlen("attributes-charset"))
            || safe_memmem(px, sizeof_px, "data", strlen("data"))) {
            item->level = Output_SUCCESS;
            safe_strcpy(item->classification, OUTPUT_CLS_LEN, "ipp");
            safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
            return 0;
        }
    }
    

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not ipp");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

struct ProbeModule LzrIppProbe = {
    .name       = "lzr-ipp",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrIpp Probe sends an IPP request and identifies IPP service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_ipp_make_payload,
    .get_payload_length_cb                   = &lzr_ipp_get_payload_length,
    .validate_response_cb                    = NULL,
    .handle_response_cb                      = &lzr_ipp_handle_reponse,
    .close_cb                                = &probe_close_nothing,
};
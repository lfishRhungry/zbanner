#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrSocks5Probe;

static char lzr_socks5_payload[] = "\x05\x04\x00\x01\x02\x80\x05\x01\x00\x03\x0agoogle.com\x00\x50GET / HTTP/1.0\r\n\r\n";

static size_t
lzr_socks5_make_payload(
    ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_socks5_payload, sizeof(lzr_socks5_payload)-1);
    return sizeof(lzr_socks5_payload)-1;
}

static size_t
lzr_socks5_get_payload_length(ProbeTarget *target)
{
    return sizeof(lzr_socks5_payload)-1;
}

static unsigned
lzr_socks5_handle_reponse(
    unsigned th_idx,
    ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    OutItem *item)
{
    if (sizeof_px==2 && px[0]=='\x05' && (px[1]=='\xff'||px[1]=='\x00')) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "socks5");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    if (sizeof_px<4) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "not socks5");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");
        return 0;
    }

    if (px[0]=='\x05' && (px[1]=='\x01'||px[1]=='\x02')) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "socks5");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    if (bytes_equals(px, sizeof_px, "\x05\0\x05", sizeof("\x05\0\x05")-1)
        && px[3]<=8) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "socks5");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not socks5");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_socks5_handle_timeout(ProbeTarget *target, OutItem *item)
{
    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not socks5");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

Probe LzrSocks5Probe = {
    .name       = "lzr-socks5",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrSocks5 Probe sends an socks5 probe with google.com http request and "
        "identifies socks5 service.",
    .init_cb                                 = &probe_init_nothing,
    .make_payload_cb                         = &lzr_socks5_make_payload,
    .get_payload_length_cb                   = &lzr_socks5_get_payload_length,
    .handle_response_cb                      = &lzr_socks5_handle_reponse,
    .handle_timeout_cb                       = &lzr_socks5_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
/**
 * modified from LZR by sharkocha 2024
 */
#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrX11Probe;

static char lzr_x11_payload[] =
    "\x6c\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00";

static size_t lzr_x11_make_payload(ProbeTarget   *target,
                                   unsigned char *payload_buf) {
    memcpy(payload_buf, lzr_x11_payload, sizeof(lzr_x11_payload) - 1);
    return sizeof(lzr_x11_payload) - 1;
}

static size_t lzr_x11_get_payload_length(ProbeTarget *target) {
    return sizeof(lzr_x11_payload) - 1;
}

static unsigned lzr_x11_handle_reponse(unsigned th_idx, ProbeTarget *target,
                                       const unsigned char *px,
                                       unsigned sizeof_px, OutItem *item) {
    /**
     * from nmap fingerprints:
     * softmatch X11 m|^\x01\0\x0b\0\0......\0\0\0.|s
     */

    if (sizeof_px < 15) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "not x11");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");
    }

    if (bytes_equals(px, sizeof_px, "\x01\x00\x0b\x00\x00", 5)) {
        if (bytes_equals(px + 11, sizeof_px - 11, "\x00\x00\x00", 3)) {
            item->level = OUT_SUCCESS;
            safe_strcpy(item->classification, OUT_CLS_SIZE, "x11");
            safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        }
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not x11");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned lzr_x11_handle_timeout(ProbeTarget *target, OutItem *item) {
    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not x11");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

Probe LzrX11Probe = {
    .name       = "lzr-x11",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc = "LzrX11 Probe sends an X11 probe and identifies service by other "
            "probes.",

    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &lzr_x11_make_payload,
    .get_payload_length_cb = &lzr_x11_get_payload_length,
    .handle_response_cb    = &lzr_x11_handle_reponse,
    .handle_timeout_cb     = &lzr_x11_handle_timeout,
    .close_cb              = &probe_close_nothing,
};
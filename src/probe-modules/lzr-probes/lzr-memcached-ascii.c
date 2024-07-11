#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrMemcachedAsciiProbe;

static char lzr_mema_payload[] = "stats\r\n";

static size_t lzr_mema_make_payload(ProbeTarget   *target,
                                    unsigned char *payload_buf) {
    memcpy(payload_buf, lzr_mema_payload, strlen(lzr_mema_payload));
    return strlen(lzr_mema_payload);
}

static size_t lzr_mema_get_payload_length(ProbeTarget *target) {
    return strlen(lzr_mema_payload);
}

static unsigned lzr_mema_handle_reponse(unsigned th_idx, ProbeTarget *target,
                                        const unsigned char *px,
                                        unsigned sizeof_px, OutItem *item) {
    if (safe_memmem(px, sizeof_px, "STAT", strlen("STAT")) &&
        safe_memmem(px, sizeof_px, "pid", strlen("pid"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "memcached_ascii");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not memcached_ascii");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned lzr_mema_handle_timeout(ProbeTarget *target, OutItem *item) {
    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not memcached_ascii");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

Probe LzrMemcachedAsciiProbe = {
    .name       = "lzr-memcached_ascii",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrMemcachedAscii Probe sends a Memcached ASCII request and identifies"
        " Memcached ASCII service.",

    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &lzr_mema_make_payload,
    .get_payload_length_cb = &lzr_mema_get_payload_length,
    .handle_response_cb    = &lzr_mema_handle_reponse,
    .handle_timeout_cb     = &lzr_mema_handle_timeout,
    .close_cb              = &probe_close_nothing,
};
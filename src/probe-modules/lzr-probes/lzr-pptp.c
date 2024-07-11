#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrPptpProbe;

static char lzr_pptp_payload[] = {
    0, 156, 0,   1, 26, 43, 60, 77, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
    1, 255, 255, 0, 1,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0,   0,   0, 0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0,   0,   0, 0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0,   0,   0, 0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0,   0,   0, 0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0,   0,   0, 0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static size_t lzr_pptp_make_payload(ProbeTarget   *target,
                                    unsigned char *payload_buf) {
    memcpy(payload_buf, lzr_pptp_payload, sizeof(lzr_pptp_payload));
    return sizeof(lzr_pptp_payload);
}

static size_t lzr_pptp_get_payload_length(ProbeTarget *target) {
    return sizeof(lzr_pptp_payload);
}

static unsigned lzr_pptp_handle_reponse(unsigned th_idx, ProbeTarget *target,
                                        const unsigned char *px,
                                        unsigned sizeof_px, OutItem *item) {
    if (safe_memmem(px, sizeof_px, "+<M", strlen("+<M"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "pptp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not pptp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned lzr_pptp_handle_timeout(ProbeTarget *target, OutItem *item) {
    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not pptp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

Probe LzrPptpProbe = {
    .name       = "lzr-pptp",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc = "LzrPptp Probe sends a PPTP probe and identifies PPTP service.",

    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &lzr_pptp_make_payload,
    .get_payload_length_cb = &lzr_pptp_get_payload_length,
    .handle_response_cb    = &lzr_pptp_handle_reponse,
    .handle_timeout_cb     = &lzr_pptp_handle_timeout,
    .close_cb              = &probe_close_nothing,
};
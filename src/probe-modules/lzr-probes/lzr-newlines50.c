#include "../probe-modules.h"

#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrNewlines50Probe;

static char lzr_newlines50_payload[] =
    "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
    "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";

static size_t lzr_newlines50_make_payload(ProbeTarget   *target,
                                          unsigned char *payload_buf) {
    memcpy(payload_buf, lzr_newlines50_payload, strlen(lzr_newlines50_payload));
    return strlen(lzr_newlines50_payload);
}

static size_t lzr_newlines50_get_payload_length(ProbeTarget *target) {
    return strlen(lzr_newlines50_payload);
}

static unsigned lzr_newlines50_handle_response(unsigned             th_idx,
                                               ProbeTarget         *target,
                                               const unsigned char *px,
                                               unsigned             sizeof_px,
                                               OutItem             *item) {
    item->level = OUT_FAILURE;

    safe_strcpy(item->classification, OUT_CLS_SIZE, "unknown");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

Probe LzrNewlines50Probe = {
    .name       = "lzr-newlines50",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc = "LzrNewlines50 Probe sends 50 newlines and identifies services by "
            "other probes.",

    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &lzr_newlines50_make_payload,
    .get_payload_length_cb = &lzr_newlines50_get_payload_length,
    .handle_response_cb    = &lzr_newlines50_handle_response,
    .close_cb              = &probe_close_nothing,
};

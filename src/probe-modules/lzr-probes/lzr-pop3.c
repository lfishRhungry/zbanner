#include "../probe-modules.h"

#include <string.h>

#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrPop3Probe;

static unsigned lzr_pop3_handle_response(unsigned th_idx, ProbeTarget *target,
                                         const unsigned char *px,
                                         unsigned sizeof_px, OutItem *item) {
    /**
     * ref to nmap.
     * must be compatible with lzr-imap
     */
    if (safe_memismem(px, sizeof_px, "pop3", strlen("pop3"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "pop3");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not pop3");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

Probe LzrPop3Probe = {
    .name       = "lzr-pop3",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc       = "LzrPop3 Probe sends no payload and identifies POP3 service.",

    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &probe_make_no_payload,
    .get_payload_length_cb = &probe_no_payload_length,
    .handle_response_cb    = &lzr_pop3_handle_response,
    .close_cb              = &probe_close_nothing,
};
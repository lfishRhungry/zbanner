#include "../probe-modules.h"

#include <string.h>

#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrFtpProbe;

static unsigned lzr_ftp_handle_response(unsigned th_idx, ProbeTarget *target,
                                        const unsigned char *px,
                                        unsigned sizeof_px, OutItem *item) {
    if (safe_memismem(px, sizeof_px, "ftp", strlen("ftp")) ||
        safe_memmem(px, sizeof_px, "conv_code ret failed",
                    strlen("conv_code ret failed"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "ftp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    /**
     * ref to nmap.
     * must be compatible with rules of lzr-smtp.
     */

    if (safe_bytes_equals(px, sizeof_px, "220", 3) &&
        !safe_memismem(px, sizeof_px, "mail", strlen("mail")) &&
        !safe_memismem(px, sizeof_px, "smtp", strlen("smtp"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "ftp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    if (safe_bytes_equals(px, sizeof_px, "501", 3) ||
        safe_bytes_equals(px, sizeof_px, "500", 3)) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "ftp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not ftp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

Probe LzrFtpProbe = {
    .name       = "lzr-ftp",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc       = "LzrFtp Probe sends no payload and identifies FTP service.",

    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &probe_make_no_payload,
    .get_payload_length_cb = &probe_no_payload_length,
    .handle_response_cb    = &lzr_ftp_handle_response,
    .close_cb              = &probe_close_nothing,
};
#include <string.h>

#include "../probe-modules.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrFtpProbe;

static unsigned
lzr_ftp_handle_response(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (safe_memismem(px, sizeof_px, "ftp", strlen("ftp"))
        || safe_memismem(px, sizeof_px, "conv_code ret failed", strlen( "conv_code ret failed"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "ftp");
        safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "matched");
        return 0;
    }

    /**
     * ref to nmap.
     * must compatible with rules of lzr-smtp.
    */
    if (bytes_equals(px, sizeof_px, "220", 3)
        ||bytes_equals(px, sizeof_px, "501", 3)
        ||bytes_equals(px, sizeof_px, "500", 3)) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "ftp");
        safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "not ftp");
    safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_ftp_handle_timeout(struct ProbeTarget *target, struct OutputItem *item)
{
    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "not ftp");
    safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "no response");
    return 0;
}

struct ProbeModule LzrFtpProbe = {
    .name       = "lzr-ftp",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrFtp Probe sends no payload and identifies FTP service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &probe_make_no_payload,
    .get_payload_length_cb                   = &probe_no_payload_length,
    .handle_response_cb                      = &lzr_ftp_handle_response,
    .handle_timeout_cb                       = &lzr_ftp_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
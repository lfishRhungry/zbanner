#include <string.h>

#include "../probe-modules.h"
#include "../../util/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrFtpProbe;

static int
lzr_ftp_handle_response(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not ftp");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }
    
    if (safe_memismem(px, sizeof_px, "ftp", strlen("ftp"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "ftp");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    /* This matching is like fallback condition in Nmap*/
    char tmp_str[4] = {px[0], px[1], px[2], '\0'};
    if (strstr(tmp_str, "220")
        || strstr(tmp_str, "421")
        || strstr(tmp_str, "530")
        || strstr(tmp_str, "550")
        || strstr(tmp_str, "230")) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "ftp");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not ftp");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

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
    .global_init_cb                       = &probe_init_nothing,
    .make_payload_cb                      = &probe_make_no_payload,
    .get_payload_length_cb                = &probe_no_payload_length,
    .validate_response_cb                 = NULL,
    .handle_response_cb                   = &lzr_ftp_handle_response,
    .close_cb                             = &probe_close_nothing,
};
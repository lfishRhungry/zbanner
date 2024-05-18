#include <string.h>

#include "../probe-modules.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrTelnetProbe;

static unsigned
lzr_telnet_handle_response(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{

    if (sizeof_px<2) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "not telnet");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");
        return 0;
    }
    
    if (safe_memismem(px, sizeof_px, "telnet", strlen("telnet"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "telnet");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    /**
     * fixed from LZR by lfishRhungry 2024
    */
    if (px[1]==0xff && (px[1]==0xfe || px[1]==0xfd || px[1]==0xfc || px[1]==0xfb)) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "telnet");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }


    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not telnet");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_telnet_handle_timeout(struct ProbeTarget *target, struct OutputItem *item)
{
    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not telnet");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

struct ProbeModule LzrTelnetProbe = {
    .name       = "lzr-telnet",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrTelnet Probe sends no payload and identifies Telnet service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &probe_make_no_payload,
    .get_payload_length_cb                   = &probe_no_payload_length,
    .handle_response_cb                      = &lzr_telnet_handle_response,
    .handle_timeout_cb                       = &lzr_telnet_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
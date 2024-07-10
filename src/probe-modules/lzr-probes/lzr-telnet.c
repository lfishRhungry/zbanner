#include <string.h>

#include "../probe-modules.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrTelnetProbe;

static unsigned
lzr_telnet_handle_response(
    unsigned th_idx,
    ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    OutItem *item)
{

    if (sizeof_px<2) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "not telnet");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");
        return 0;
    }

    if (safe_memismem(px, sizeof_px, "telnet", strlen("telnet"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "telnet");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    /**
     * simple rule fixed from LZR and ref to nmap
     * by sharkocha 2024
    */
    if (px[0]==0xff && (px[1]==0xfe || px[1]==0xfd || px[1]==0xfc || px[1]==0xfb)) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "telnet");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }


    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not telnet");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_telnet_handle_timeout(ProbeTarget *target, OutItem *item)
{
    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not telnet");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

Probe LzrTelnetProbe = {
    .name       = "lzr-telnet",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrTelnet Probe sends no payload and identifies Telnet service.",
    .init_cb                                 = &probe_init_nothing,
    .make_payload_cb                         = &probe_make_no_payload,
    .get_payload_length_cb                   = &probe_no_payload_length,
    .handle_response_cb                      = &lzr_telnet_handle_response,
    .handle_timeout_cb                       = &lzr_telnet_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
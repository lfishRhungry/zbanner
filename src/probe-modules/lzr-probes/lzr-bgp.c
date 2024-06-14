/**
 * Add to LZR by sharkocha 2024
*/
#include <string.h>

#include "../probe-modules.h"
#include "../../util-data/safe-string.h"

#define BGP_PREFIX "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

/*for internal x-ref*/
extern struct ProbeModule LzrBgpProbe;


static unsigned
lzr_bgp_handle_response(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{

    if (sizeof_px<20) {
        item->level = OP_FAILURE;
        safe_strcpy(item->classification, OP_CLS_SIZE, "not bgp");
        safe_strcpy(item->reason, OP_RSN_SIZE, "not matched");
        return 0;
    }

    if (bytes_equals(px, sizeof_px, BGP_PREFIX, sizeof(BGP_PREFIX)-1)) {
        if (bytes_equals(px+16, sizeof_px-16, "\x00\x15\x03\x06", 4)
            || bytes_equals(px+16, sizeof_px-16, "\x00\x1d\x01\x04", 4)
            || bytes_equals(px+18, sizeof_px-18, "\x01\x04", 2)) {
            item->level = OP_SUCCESS;
            safe_strcpy(item->classification, OP_CLS_SIZE, "bgp");
            safe_strcpy(item->reason, OP_RSN_SIZE, "matched");
            return 0;
        }
    }

    item->level = OP_FAILURE;
    safe_strcpy(item->classification, OP_CLS_SIZE, "not bgp");
    safe_strcpy(item->reason, OP_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_bgp_handle_timeout(struct ProbeTarget *target, struct OutputItem *item)
{
    item->level = OP_FAILURE;
    safe_strcpy(item->classification, OP_CLS_SIZE, "not bgp");
    safe_strcpy(item->reason, OP_RSN_SIZE, "no response");
    return 0;
}

struct ProbeModule LzrBgpProbe = {
    .name       = "lzr-bgp",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrBgp Probe sends no payload and identifies BGP service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &probe_make_no_payload,
    .get_payload_length_cb                   = &probe_no_payload_length,
    .handle_response_cb                      = &lzr_bgp_handle_response,
    .handle_timeout_cb                       = &lzr_bgp_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
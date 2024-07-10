#include "../probe-modules.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrWaitProbe;

static unsigned
lzr_wait_handle_response(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    OutItem *item)
{
    item->level = OUT_FAILURE;

    safe_strcpy(item->classification, OUT_CLS_SIZE, "unknown");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_wait_handle_timeout(struct ProbeTarget *target, OutItem *item)
{
    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "unknown");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

struct ProbeModule LzrWaitProbe = {
    .name       = "lzr-wait",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrWait Probe sends nothing and identifies no service. It is the default\n"
        "subprobe of LzrProbe to help other subprobes to match services.",
    .init_cb                                 = &probe_init_nothing,
    .make_payload_cb                         = &probe_make_no_payload,
    .get_payload_length_cb                   = &probe_no_payload_length,
    .handle_response_cb                      = &lzr_wait_handle_response,
    .handle_timeout_cb                       = &lzr_wait_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};

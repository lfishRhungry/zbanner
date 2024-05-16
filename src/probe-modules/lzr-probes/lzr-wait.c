#include "../probe-modules.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrWaitProbe;

static unsigned
lzr_wait_handle_response(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    item->level = Output_FAILURE;

    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

static unsigned
lzr_wait_handle_timeout(struct ProbeTarget *target, struct OutputItem *item)
{
    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
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
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &probe_make_no_payload,
    .get_payload_length_cb                   = &probe_no_payload_length,
    .handle_response_cb                      = &lzr_wait_handle_response,
    .handle_timeout_cb                       = &lzr_wait_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};

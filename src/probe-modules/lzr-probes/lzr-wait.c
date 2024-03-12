#include "../probe-modules.h"
#include "../../util/mas-safefunc.h"

/*for internal x-ref*/
extern struct ProbeModule LzrWaitProbe;

static int
lzr_wait_handle_response(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    item->level = Output_FAILURE;

    if (sizeof_px==0) {
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }
    
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

struct ProbeModule LzrWaitProbe = {
    .name       = "lzr-wait",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .desc =
        "LzrWait Probe sends nothing and identifies no service. It is the default\n"
        "subprobe of LzrProbe to help other subprobes to match services.\n",
    .global_init_cb                         = &probe_init_nothing,
    .make_payload_cb                        = &probe_make_no_payload,
    .get_payload_length_cb                  = &probe_no_payload_length,
    .validate_response_cb                   = NULL,
    .handle_response_cb                     = &lzr_wait_handle_response,
    .close_cb                               = &probe_close_nothing,
};

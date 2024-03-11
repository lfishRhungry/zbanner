#include "../probe-modules.h"

/*for internal x-ref*/
extern struct ProbeModule LzrWaitProbe;

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
    .handle_response_cb                     = &probe_report_nothing,
    .close_cb                               = &probe_close_nothing,
};

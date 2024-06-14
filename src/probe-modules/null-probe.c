#include "probe-modules.h"

/*for internal x-ref*/
extern struct ProbeModule NullProbe;

struct ProbeModule NullProbe = {
    .name       = "null",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "NullProbe does not send any data to target port. It just wait banner "
        "from server. However, waiting is the cheapest thing while we are in "
        "stateless mode.",
    .init_cb                                 = &probe_init_nothing,
    .make_payload_cb                         = &probe_make_no_payload,
    .get_payload_length_cb                   = &probe_no_payload_length,
    .handle_response_cb                      = &probe_just_report_banner,
    .handle_timeout_cb                       = &probe_no_timeout,
    .close_cb                                = &probe_close_nothing,
};
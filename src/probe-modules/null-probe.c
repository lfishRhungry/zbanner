#include "probe-modules.h"

/*for internal x-ref*/
extern struct ProbeModule NullProbe;

struct ProbeModule NullProbe = {
    .name = "null",
    .type = ProbeType_TCP,
    .desc =
        "NullProbe does not send any data to target port. It just wait banner "
        "from server. However, waiting is the cheapest thing while we are in "
        "stateless mode.\n",
    .global_init_cb = NULL,
    .rx_thread_init_cb = NULL,
    .tx_thread_init_cb = NULL,
    .make_payload_cb = NULL,
    .get_payload_length_cb = &no_payload_length,
    .validate_response_cb = NULL,
    .handle_response_cb = &just_report_banner,
    .close_cb = NULL
};
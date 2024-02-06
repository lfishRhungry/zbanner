#include "../probe-modules.h"

/*for internal x-ref*/
extern struct ProbeModule LzrWaitProbe;

struct ProbeModule LzrWaitProbe = {
    .name = "lzr-wait",
    .type = ProbeType_TCP,
    .desc =
        "LzrWait Probe sends nothing and identifies no service. It is the default\n"
        "subprobe of LzrProbe to help other subprobes to match services.\n",
    .global_init_cb = NULL,
    .rx_thread_init_cb = NULL,
    .tx_thread_init_cb = NULL,
    .make_payload_cb = NULL,
    .validate_response_cb = NULL,
    .handle_response_cb = NULL,
    .close_cb = NULL
};

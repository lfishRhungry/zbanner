#include "../null-probe.h"
#include "lzr-wait.h"

/*for internal x-ref*/
extern struct ProbeModule LzrWaitProbe;

static size_t
lzrwait_get_payload_length(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me)
{
    return 0;
}

struct ProbeModule LzrWaitProbe = {
    .name = "lzr-wait",
    .type = ProbeType_TCP,
    .desc =
        "LzrWait Probe sends nothing and identifies no service. It is the default\n"
        "subprobe of LzrProbe to help other subprobes to match services.\n",
    .global_init_cb = NULL,
    .rx_thread_init_cb = NULL,
    .tx_thread_init_cb = NULL,
    .make_payload_cb = &make_no_payload,
    .get_payload_length_cb = &lzrwait_get_payload_length,
    .validate_response_cb = NULL,
    .handle_response_cb = NULL,
    .close_cb = NULL
};

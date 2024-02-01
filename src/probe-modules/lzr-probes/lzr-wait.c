#include "../../xconf.h"
#include "../null-probe.h"
#include "lzr-wait.h"

struct ProbeModule LzrWaitProbe = {
    .name = "lzr-wait",
    .type = Tcp_Probe,
    .help_text =
        "LzrWait Probe sends nothing and identifies no service. It is the default\n"
        "subprobe of LzrProbe to help other subprobes to match services.\n",
    .global_init_cb = NULL,
    .thread_init_cb = NULL,
    .make_payload_cb = &make_no_payload,
    .get_payload_length_cb = &null_get_payload_length,
    .get_report_banner_cb = &report_no_banner,
    .close_cb = NULL
};


size_t
report_no_banner(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me,
    const unsigned char *banner, size_t banner_len,
    unsigned char *report_banner_buf, size_t buf_len)
{
    return 0;
}
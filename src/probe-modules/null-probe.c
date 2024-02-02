#include "null-probe.h"
#include "../util/mas-safefunc.h"

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
    .make_payload_cb = &make_no_payload,
    .validate_response_cb = NULL,
    .handle_response_cb = &just_report_banner,
    .close_cb = NULL
};

size_t
make_no_payload(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned cookie,
    unsigned char *payload_buf,
    size_t buf_length)
{
    return 0;
}

void
just_report_banner(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    const unsigned char *px, unsigned sizeof_px,
    unsigned *successed,
    char *classification, unsigned cls_length,
    char *report, unsigned rpt_length)
{
    *successed = 1;
    safe_strcpy(classification, cls_length, "banner");
    normalize_string(px, sizeof_px, report, rpt_length);
}
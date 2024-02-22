#include "probe-modules.h"
#include "../util/mas-safefunc.h"

/*for internal x-ref*/
extern struct ProbeModule EchoProbe;

static size_t
echo_make_payload(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned cookie, unsigned idx,
    unsigned char *payload_buf,
    size_t buf_length)
{
    payload_buf[0] = cookie >> 24;
    payload_buf[1] = cookie >> 16;
    payload_buf[2] = cookie >>  8;
    payload_buf[3] = cookie >>  0;

    return 4;
}

static int
echo_validate_response(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned cookie, unsigned idx,
    const unsigned char *px, unsigned sizeof_px)
{
    unsigned char needle[4];
    needle[0] = cookie >> 24;
    needle[1] = cookie >> 16;
    needle[2] = cookie >>  8;
    needle[3] = cookie >>  0;

    if (safe_memmem(needle, 4, px, sizeof_px))
        return 1;

    return 0;
}

struct ProbeModule EchoProbe = {
    .name      = "echo",
    .type      = ProbeType_UDP,
    .probe_num = 1,
    .desc =
        "EchoProbe sends 4 bytes of random data to target udp port and expects "
        "response that contains our random data.\n"
        "EchoProbe could be used for finding UDP echo service or alive hosts "
        "by icmp port unreachable messages. Its `validate_reponsed_cb` cannot be "
        "used when making a ScanModule if you like.\n",
    .global_init_cb                 = &probe_init_nothing,
    .make_payload_cb                = &echo_make_payload,
    .get_payload_length_cb          = NULL,
    .validate_response_cb           = &echo_validate_response,
    .handle_response_cb             = &probe_just_report_banner,
    .close_cb                       = &probe_close_nothing,
};
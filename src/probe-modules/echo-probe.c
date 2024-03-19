#include "probe-modules.h"
#include "../util/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule EchoProbe;

static size_t
echo_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    payload_buf[0] = target->cookie >> 24;
    payload_buf[1] = target->cookie >> 16;
    payload_buf[2] = target->cookie >>  8;
    payload_buf[3] = target->cookie >>  0;

    return 4;
}

static int
echo_validate_response(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px)
{
    if (sizeof_px==0) {
        return 0;
    }

    unsigned char needle[4];
    needle[0] = target->cookie >> 24;
    needle[1] = target->cookie >> 16;
    needle[2] = target->cookie >>  8;
    needle[3] = target->cookie >>  0;

    if (safe_memmem(px, sizeof_px, needle, 4))
        return 1;

    return 0;
}

struct ProbeModule EchoProbe = {
    .name       = "echo",
    .type       = ProbeType_UDP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "EchoProbe sends 4 bytes of random data to target udp port and expects "
        "response that contains our random data.\n"
        "EchoProbe could be used for finding UDP echo service or alive hosts "
        "by icmp port unreachable messages. Its `validate_reponsed_cb` cannot be "
        "used when making a ScanModule if you like.",
    .global_init_cb                 = &probe_global_init_nothing,
    .make_payload_cb                = &echo_make_payload,
    .get_payload_length_cb          = NULL,
    .validate_response_cb           = &echo_validate_response,
    .handle_response_cb             = &probe_just_report_banner,
    .close_cb                       = &probe_close_nothing,
};
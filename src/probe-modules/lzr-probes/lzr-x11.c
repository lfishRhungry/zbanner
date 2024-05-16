#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrX11Probe;

static char lzr_x11_payload[] =
"\x6c\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00";


static size_t
lzr_x11_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_x11_payload, sizeof(lzr_x11_payload)-1);
    return sizeof(lzr_x11_payload)-1;
}

static size_t
lzr_x11_get_payload_length(struct ProbeTarget *target)
{
    return sizeof(lzr_x11_payload)-1;
}

static unsigned
lzr_x11_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    item->level = Output_FAILURE;
    if (sizeof_px<15) {}
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

static unsigned
lzr_x11_handle_timeout(struct ProbeTarget *target, struct OutputItem *item)
{
    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not x11");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
    return 0;
}

struct ProbeModule LzrX11Probe = {
    .name       = "lzr-x11",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrX11 Probe sends an X11 probe and identifies service by other probes.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_x11_make_payload,
    .get_payload_length_cb                   = &lzr_x11_get_payload_length,
    .handle_response_cb                      = &lzr_x11_handle_reponse,
    .handle_timeout_cb                       = &lzr_x11_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
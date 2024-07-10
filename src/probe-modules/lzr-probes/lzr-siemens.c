#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrSiemensProbe;

static char lzr_siemens_payload[] =
"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x04\x00\xc1"
"\x02\x01\x00\xc2\x02\x02\x00\xc0\x01\x0a";


static size_t
lzr_siemens_make_payload(
    ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_siemens_payload, sizeof(lzr_siemens_payload)-1);
    return sizeof(lzr_siemens_payload)-1;
}

static size_t
lzr_siemens_get_payload_length(ProbeTarget *target)
{
    return sizeof(lzr_siemens_payload)-1;
}

static unsigned
lzr_siemens_handle_reponse(
    unsigned th_idx,
    ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    OutItem *item)
{

    if (sizeof_px>=6 && px[4]+1==sizeof_px-4 && px[5]==0xd0) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "siemens");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not siemens");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_siemens_handle_timeout(ProbeTarget *target, OutItem *item)
{
    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not siemens");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

Probe LzrSiemensProbe = {
    .name       = "lzr-siemens",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrSiemens Probe sends an Siemens probe and identifies Siemens service.",
    .init_cb                                 = &probe_init_nothing,
    .make_payload_cb                         = &lzr_siemens_make_payload,
    .get_payload_length_cb                   = &lzr_siemens_get_payload_length,
    .handle_response_cb                      = &lzr_siemens_handle_reponse,
    .handle_timeout_cb                       = &lzr_siemens_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
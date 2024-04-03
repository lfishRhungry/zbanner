#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrSiemensProbe;

static char lzr_siemens_payload[] =
"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x04\x00\xc1"
"\x02\x01\x00\xc2\x02\x02\x00\xc0\x01\x0a";


static size_t
lzr_siemens_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_siemens_payload, sizeof(lzr_siemens_payload)-1);
    return sizeof(lzr_siemens_payload)-1;
}

static size_t
lzr_siemens_get_payload_length(struct ProbeTarget *target)
{
    return sizeof(lzr_siemens_payload)-1;
}

static unsigned
lzr_siemens_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not siemens");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }

    if (sizeof_px>=6 && px[4]+1==sizeof_px-4 && px[5]==0xd0) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "siemens");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not siemens");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

struct ProbeModule LzrSiemensProbe = {
    .name       = "lzr-siemens",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrSiemens Probe sends an Siemens probe and identifies Siemens service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_siemens_make_payload,
    .get_payload_length_cb                   = &lzr_siemens_get_payload_length,
    .validate_response_cb                    = NULL,
    .handle_response_cb                      = &lzr_siemens_handle_reponse,
    .close_cb                                = &probe_close_nothing,
};
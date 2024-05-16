#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrRdpProbe;

static char lzr_rdp_payload[] =
"\x03\x00\x00\x26\x21\xe0\x00\x00\xfe\xca\x00\x43"
"\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73\x74\x73\x68"
"\x61\x73\x68\x3d\x0d\x0a\x01\x00\x08\x00\x01\x00\x00\x00";

static char lzr_rdp_verify[] = "\x03\x00\x00\x13\x0e\xd0\xfe\xca\x12\x34";


static size_t
lzr_rdp_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_rdp_payload, sizeof(lzr_rdp_payload)-1);
    return sizeof(lzr_rdp_payload)-1;
}

static size_t
lzr_rdp_get_payload_length(struct ProbeTarget *target)
{
    return sizeof(lzr_rdp_payload)-1;
}

static unsigned
lzr_rdp_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{

    if (sizeof_px>=11
        && bytes_equals(px, sizeof_px, lzr_rdp_verify, sizeof(lzr_rdp_verify)-1)) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "rdp");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not rdp");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

static unsigned
lzr_rdp_handle_timeout(struct ProbeTarget *target, struct OutputItem *item)
{
    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not rdp");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
    return 0;
}

struct ProbeModule LzrRdpProbe = {
    .name       = "lzr-rdp",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrRdp Probe sends an RDP probe and identifies RDP service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_rdp_make_payload,
    .get_payload_length_cb                   = &lzr_rdp_get_payload_length,
    .handle_response_cb                      = &lzr_rdp_handle_reponse,
    .handle_timeout_cb                       = &lzr_rdp_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
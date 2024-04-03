#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrOracleProbe;

static char lzr_oracle_payload[] =
"\x00\x6d\x00\x00\x01\x00\x00\x00\x01\x38\x01\x2c\x0c\x41\x20"
"\x00\xff\xff\x7f\x08\x00\x00\x01\x00\x00\x33\x00\x3a\x00\x00"
"\x08\x00\x41\x41\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x28\x44"
"\x45\x53\x43\x52\x49\x50\x54\x49\x4f\x4e\x3d\x28\x43\x4f\x4e"
"\x4e\x45\x43\x54\x5f\x44\x41\x54\x41\x3d\x28\x43\x49\x44\x3d"
"\x28\x50\x52\x4f\x47\x52\x41\x4d\x3d\x6c\x7a\x72\x4f\x52\x41"
"\x29\x29\x29\x29";

static size_t
lzr_oracle_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_oracle_payload, sizeof(lzr_oracle_payload)-1);
    return sizeof(lzr_oracle_payload)-1;
}

static size_t
lzr_oracle_get_payload_length(struct ProbeTarget *target)
{
    return sizeof(lzr_oracle_payload)-1;
}

static unsigned
lzr_oracle_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not oracle");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }

    if (safe_memmem(px, sizeof_px, "DESCRIPTION=(", strlen("DESCRIPTION=("))
        && safe_memmem(px, sizeof_px, "(EMFI=4", strlen("(EMFI=4"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "oracle");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not oracle");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

struct ProbeModule LzrOracleProbe = {
    .name       = "lzr-oracle",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrOracle Probe sends an Oracle SQL probe and identifies Oracle SQL service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_oracle_make_payload,
    .get_payload_length_cb                   = &lzr_oracle_get_payload_length,
    .validate_response_cb                    = NULL,
    .handle_response_cb                      = &lzr_oracle_handle_reponse,
    .close_cb                                = &probe_close_nothing,
};
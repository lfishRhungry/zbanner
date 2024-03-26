#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrSmbProbe;

static char lzr_smb_payload[] =
"\x00\x00\x00\x27\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x0e\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30"
"\x2e\x31\x32\x00";


static size_t
lzr_smb_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_smb_payload, sizeof(lzr_smb_payload)-1);
    return sizeof(lzr_smb_payload)-1;
}

static size_t
lzr_smb_get_payload_length(struct ProbeTarget *target)
{
    return sizeof(lzr_smb_payload)-1;
}

static int
lzr_smb_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not smb");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }

    if (safe_memmem(px, sizeof_px, "SMB", strlen("SMB"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "smb");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not smb");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

struct ProbeModule LzrSmbProbe = {
    .name       = "lzr-smb",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrSmb Probe sends an Smb probe and identifies SMB service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_smb_make_payload,
    .get_payload_length_cb                   = &lzr_smb_get_payload_length,
    .validate_response_cb                    = NULL,
    .handle_response_cb                      = &lzr_smb_handle_reponse,
    .close_cb                                = &probe_close_nothing,
};
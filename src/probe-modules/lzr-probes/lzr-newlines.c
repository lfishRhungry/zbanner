#include "../probe-modules.h"
#include "../../util/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrNewlinesProbe;

static char lzr_newlines_payload[] = "\n\n";

static size_t
lzr_newlines_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_newlines_payload, strlen(lzr_newlines_payload));
    return strlen(lzr_newlines_payload);
}

static size_t
lzr_newlines_get_payload_length(struct ProbeTarget *target)
{
    return strlen(lzr_newlines_payload);
}

static int
lzr_newlines_handle_response(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    item->level = Output_FAILURE;

    if (sizeof_px==0) {
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }
    
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

struct ProbeModule LzrNewlinesProbe = {
    .name       = "lzr-newlines",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrNewlines Probe sends 2 newlines and identifies services by other probes.",
    .global_init_cb                         = &probe_global_init_nothing,
    .make_payload_cb                        = &lzr_newlines_make_payload,
    .get_payload_length_cb                  = &lzr_newlines_get_payload_length,
    .validate_response_cb                   = NULL,
    .handle_response_cb                     = &lzr_newlines_handle_response,
    .close_cb                               = &probe_close_nothing,
};
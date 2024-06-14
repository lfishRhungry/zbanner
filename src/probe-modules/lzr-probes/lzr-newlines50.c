#include "../probe-modules.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrNewlines50Probe;

static char lzr_newlines50_payload[] =
"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";

static size_t
lzr_newlines50_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_newlines50_payload, strlen(lzr_newlines50_payload));
    return strlen(lzr_newlines50_payload);
}

static size_t
lzr_newlines50_get_payload_length(struct ProbeTarget *target)
{
    return strlen(lzr_newlines50_payload);
}

static unsigned
lzr_newlines50_handle_response(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    item->level = OP_FAILURE;

    safe_strcpy(item->classification, OP_CLS_SIZE, "unknown");
    safe_strcpy(item->reason, OP_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_newlines50_handle_timeout(struct ProbeTarget *target, struct OutputItem *item)
{
    item->level = OP_FAILURE;
    safe_strcpy(item->classification, OP_CLS_SIZE, "unknown");
    safe_strcpy(item->reason, OP_RSN_SIZE, "no response");
    return 0;
}

struct ProbeModule LzrNewlines50Probe = {
    .name       = "lzr-newlines50",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrNewlines50 Probe sends 50 newlines and identifies services by other probes.",
    .init_cb                                 = &probe_init_nothing,
    .make_payload_cb                         = &lzr_newlines50_make_payload,
    .get_payload_length_cb                   = &lzr_newlines50_get_payload_length,
    .handle_response_cb                      = &lzr_newlines50_handle_response,
    .handle_timeout_cb                       = &lzr_newlines50_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};

#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrSmtpProbe;

static char lzr_smtp_payload[] =
"\x45\x48\x4c\x4f\x0d\x0a";


static size_t
lzr_smtp_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_smtp_payload, sizeof(lzr_smtp_payload)-1);
    return sizeof(lzr_smtp_payload)-1;
}

static size_t
lzr_smtp_get_payload_length(struct ProbeTarget *target)
{
    return sizeof(lzr_smtp_payload)-1;
}

static unsigned
lzr_smtp_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not smtp");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }

    if (safe_memismem(px, sizeof_px, "smtp", strlen("smtp"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "smtp");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not smtp");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

struct ProbeModule LzrSmtpProbe = {
    .name       = "lzr-smtp",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrSmtp Probe sends an SMTP probe and identifies SMTP service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_smtp_make_payload,
    .get_payload_length_cb                   = &lzr_smtp_get_payload_length,
    .validate_response_cb                    = NULL,
    .handle_response_cb                      = &lzr_smtp_handle_reponse,
    .close_cb                                = &probe_close_nothing,
};
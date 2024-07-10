#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrSmtpProbe;

static char lzr_smtp_payload[] =
"\x45\x48\x4c\x4f\x0d\x0a";


static size_t
lzr_smtp_make_payload(
    ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_smtp_payload, sizeof(lzr_smtp_payload)-1);
    return sizeof(lzr_smtp_payload)-1;
}

static size_t
lzr_smtp_get_payload_length(ProbeTarget *target)
{
    return sizeof(lzr_smtp_payload)-1;
}

static unsigned
lzr_smtp_handle_reponse(
    unsigned th_idx,
    ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    OutItem *item)
{

    if (safe_memismem(px, sizeof_px, "smtp", strlen("smtp"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "smtp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    /**
     * ref to nmap.
     * must be compatible with rules of lzr-ftp.
    */

    if (bytes_equals(px, sizeof_px, "220", 3)
        && safe_memismem(px, sizeof_px, "mail", strlen("mail"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "smtp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    /**
     * ref to nmap
     * also can start with `220`, but must contain an `smtp` or `mail`*/
    if (bytes_equals(px, sizeof_px, "572", 3)
        || bytes_equals(px, sizeof_px, "554", 3)
        || bytes_equals(px, sizeof_px, "450", 3)
        || bytes_equals(px, sizeof_px, "550", 3)) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "smtp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not smtp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_smtp_handle_timeout(ProbeTarget *target, OutItem *item)
{
    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not smtp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

Probe LzrSmtpProbe = {
    .name       = "lzr-smtp",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrSmtp Probe sends an SMTP probe and identifies SMTP service.",
    .init_cb                                 = &probe_init_nothing,
    .make_payload_cb                         = &lzr_smtp_make_payload,
    .get_payload_length_cb                   = &lzr_smtp_get_payload_length,
    .handle_response_cb                      = &lzr_smtp_handle_reponse,
    .handle_timeout_cb                       = &lzr_smtp_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
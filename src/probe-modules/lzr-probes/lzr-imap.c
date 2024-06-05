#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrImapProbe;


static unsigned
lzr_imap_handle_reponse(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{

    if (safe_memismem(px, sizeof_px, "imap", strlen("imap"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "imap");
        safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "matched");
        return 0;
    }

    /**
     * ref to nmap.
     * must be compatible with lzr-pop3
    */
    if (bytes_equals(px, sizeof_px, "* OK", strlen("* OK"))
        ||bytes_equals(px, sizeof_px, "* BYE", strlen("* BYE"))
        ||bytes_equals(px, sizeof_px, "+OK", strlen("+OK"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "imap");
        safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "not imap");
    safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_imap_handle_timeout(struct ProbeTarget *target, struct OutputItem *item)
{
    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "not imap");
    safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "no response");
    return 0;
}

struct ProbeModule LzrImapProbe = {
    .name       = "lzr-imap",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrImap Probe wait for banner and identifies IMAP service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &probe_make_no_payload,
    .get_payload_length_cb                   = &probe_no_payload_length,
    .handle_response_cb                      = &lzr_imap_handle_reponse,
    .handle_timeout_cb                       = &lzr_imap_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
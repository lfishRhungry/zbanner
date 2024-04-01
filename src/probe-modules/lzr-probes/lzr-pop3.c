#include <string.h>

#include "../probe-modules.h"
#include "../../util/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrPop3Probe;

static unsigned
lzr_pop3_handle_response(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not pop3");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }
    
    if (safe_memismem(px, sizeof_px, "pop3", strlen("pop3"))
        || safe_memmem(px, sizeof_px, "+OK", strlen("+OK"))
        || safe_memmem(px, sizeof_px, "* OK", strlen("* OK"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "pop3");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }


    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not pop3");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

struct ProbeModule LzrPop3Probe = {
    .name       = "lzr-pop3",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrPop3 Probe sends no payload and identifies POP3 service.",
    .global_init_cb                       = &probe_global_init_nothing,
    .make_payload_cb                      = &probe_make_no_payload,
    .get_payload_length_cb                = &probe_no_payload_length,
    .validate_response_cb                 = NULL,
    .handle_response_cb                   = &lzr_pop3_handle_response,
    .close_cb                             = &probe_close_nothing,
};
#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrAmqpProbe;

static char lzr_amqp_payload[] = "AMQP0100";

static size_t
lzr_amqp_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_amqp_payload, sizeof(lzr_amqp_payload)-1);
    return sizeof(lzr_amqp_payload)-1;
}

static size_t
lzr_amqp_get_payload_length(struct ProbeTarget *target)
{
    return sizeof(lzr_amqp_payload)-1;
}

static unsigned
lzr_amqp_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not amqp");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }

    if (safe_memmem(px, sizeof_px, "AMQP", strlen("AMQP"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "amqp");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not amqp");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

struct ProbeModule LzrAmqpProbe = {
    .name       = "lzr-amqp",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrAmqp Probe sends an AMQP probe and identifies AMQP service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_amqp_make_payload,
    .get_payload_length_cb                   = &lzr_amqp_get_payload_length,
    .validate_response_cb                    = NULL,
    .handle_response_cb                      = &lzr_amqp_handle_reponse,
    .close_cb                                = &probe_close_nothing,
};
#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrAmqpProbe;

static char lzr_amqp_payload[] = "AMQP0100";

static size_t
lzr_amqp_make_payload(
    ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_amqp_payload, sizeof(lzr_amqp_payload)-1);
    return sizeof(lzr_amqp_payload)-1;
}

static size_t
lzr_amqp_get_payload_length(ProbeTarget *target)
{
    return sizeof(lzr_amqp_payload)-1;
}

static unsigned
lzr_amqp_handle_reponse(
    unsigned th_idx,
    ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    OutItem *item)
{
    if (safe_memmem(px, sizeof_px, "AMQP", strlen("AMQP"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "amqp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not amqp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_amqp_handle_timeout(ProbeTarget *target, OutItem *item)
{
    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not amqp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

Probe LzrAmqpProbe = {
    .name       = "lzr-amqp",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrAmqp Probe sends an AMQP probe and identifies AMQP service.",
    .init_cb                                 = &probe_init_nothing,
    .make_payload_cb                         = &lzr_amqp_make_payload,
    .get_payload_length_cb                   = &lzr_amqp_get_payload_length,
    .handle_response_cb                      = &lzr_amqp_handle_reponse,
    .handle_timeout_cb                       = &lzr_amqp_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
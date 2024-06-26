#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrPostgresProbe;

static char lzr_postgres_payload[] =
"\x00\x00\x00\x08\x04\xd2\x16\x2f";

static size_t
lzr_postgres_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_postgres_payload, sizeof(lzr_postgres_payload)-1);
    return sizeof(lzr_postgres_payload)-1;
}

static size_t
lzr_postgres_get_payload_length(struct ProbeTarget *target)
{
    return sizeof(lzr_postgres_payload)-1;
}

static unsigned
lzr_postgres_handle_reponse(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{

    if (sizeof_px==1) {
        if (px[0]==0x4e || px[0]==0x53 || px[0]==0x45) {
            item->level = OUT_SUCCESS;
            safe_strcpy(item->classification, OUT_CLS_SIZE, "postgres");
            safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
            return 0;
        }
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not postgres");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_postgres_handle_timeout(struct ProbeTarget *target, struct OutputItem *item)
{
    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not postgres");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

struct ProbeModule LzrPostgresProbe = {
    .name       = "lzr-postgres",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrPostgres Probe sends an Postgres probe and identifies Postgres service.",
    .init_cb                                 = &probe_init_nothing,
    .make_payload_cb                         = &lzr_postgres_make_payload,
    .get_payload_length_cb                   = &lzr_postgres_get_payload_length,
    .handle_response_cb                      = &lzr_postgres_handle_reponse,
    .handle_timeout_cb                       = &lzr_postgres_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
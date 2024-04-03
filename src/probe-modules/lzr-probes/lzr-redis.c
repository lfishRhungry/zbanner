#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrRedisProbe;

static char lzr_redis_payload[] =
"\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x50\x49\x4e\x47\x0d\x0a";


static size_t
lzr_redis_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_redis_payload, sizeof(lzr_redis_payload)-1);
    return sizeof(lzr_redis_payload)-1;
}

static size_t
lzr_redis_get_payload_length(struct ProbeTarget *target)
{
    return sizeof(lzr_redis_payload)-1;
}

static unsigned
lzr_redis_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not redis");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }

    if (sizeof_px==7
        && safe_memmem(px, sizeof_px, "PONG", strlen("PONG"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "redis");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    if (safe_memmem(px, sizeof_px, "Redis", strlen("Redis"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "redis");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    if (safe_memmem(px, sizeof_px, "-ERR unknown", strlen("-ERR unknown"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "redis");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not redis");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

struct ProbeModule LzrRedisProbe = {
    .name       = "lzr-redis",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrRedis Probe sends an Redis probe and identifies Redis service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_redis_make_payload,
    .get_payload_length_cb                   = &lzr_redis_get_payload_length,
    .validate_response_cb                    = NULL,
    .handle_response_cb                      = &lzr_redis_handle_reponse,
    .close_cb                                = &probe_close_nothing,
};
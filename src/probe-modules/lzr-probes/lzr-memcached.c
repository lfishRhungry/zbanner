#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrMemcachedProbe;

//question: baidu.com
static char lzr_mem_payload[] = "stats\r\n";

static size_t
lzr_mem_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_mem_payload, strlen(lzr_mem_payload));
    return strlen(lzr_mem_payload);
}

static size_t
lzr_mem_get_payload_length(struct ProbeTarget *target)
{
    return strlen(lzr_mem_payload);
}

static int
lzr_mem_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not memcached");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }

    if (safe_memmem(px, sizeof_px, "STAT", strlen("STAT"))
        && safe_memmem(px, sizeof_px, "pid", strlen("pid"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "memcached");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not memcached");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

struct ProbeModule LzrMemcachedProbe = {
    .name       = "lzr-memcached",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrMemcached Probe sends a Memcached request and identifies Memcached service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_mem_make_payload,
    .get_payload_length_cb                   = &lzr_mem_get_payload_length,
    .validate_response_cb                    = NULL,
    .handle_response_cb                      = &lzr_mem_handle_reponse,
    .close_cb                                = &probe_close_nothing,
};
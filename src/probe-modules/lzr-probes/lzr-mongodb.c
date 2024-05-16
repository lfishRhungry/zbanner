#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrMongodbProbe;

static char lzr_mongodb_payload[] =
":\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\xd4\x07\x00\x00\x00"
"\x00\x00\x00admin.$cmd\x00\x00\x00"
"\x00\x00\x01\x00\x00\x00\x13\x00\x00"
"\x00\x10isMaster\x00\x01\x00\x00\x00\x00";

static size_t
lzr_mongodb_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_mongodb_payload, sizeof(lzr_mongodb_payload)-1);
    return sizeof(lzr_mongodb_payload)-1;
}

static size_t
lzr_mongodb_get_payload_length(struct ProbeTarget *target)
{
    return sizeof(lzr_mongodb_payload)-1;
}

static unsigned
lzr_mongodb_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{

    if (safe_memmem(px, sizeof_px, "maxBsonObjectSize", strlen( "maxBsonObjectSize"))
        && safe_memmem(px, sizeof_px, "MongoDB", strlen( "MongoDB"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "mongodb");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not mongodb");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

static unsigned
lzr_mongodb_handle_timeout(struct ProbeTarget *target, struct OutputItem *item)
{
    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not mongodb");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
    return 0;
}

struct ProbeModule LzrMongodbProbe = {
    .name       = "lzr-mongodb",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrMongodb Probe sends a mongodb probe and identifies mongodb service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_mongodb_make_payload,
    .get_payload_length_cb                   = &lzr_mongodb_get_payload_length,
    .handle_response_cb                      = &lzr_mongodb_handle_reponse,
    .handle_timeout_cb                       = &lzr_mongodb_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
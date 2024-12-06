#include "../probe-modules.h"

#include <string.h>
#include <time.h>

#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrMongodbProbe;

static char lzr_mongodb_payload[] = ":\x00\x00\x00\x00\x00\x00\x00\x00"
                                    "\x00\x00\x00\xd4\x07\x00\x00\x00"
                                    "\x00\x00\x00admin.$cmd\x00\x00\x00"
                                    "\x00\x00\x01\x00\x00\x00\x13\x00\x00"
                                    "\x00\x10isMaster\x00\x01\x00\x00\x00\x00";

static size_t lzr_mongodb_make_payload(ProbeTarget   *target,
                                       unsigned char *payload_buf) {
    memcpy(payload_buf, lzr_mongodb_payload, sizeof(lzr_mongodb_payload) - 1);
    return sizeof(lzr_mongodb_payload) - 1;
}

static size_t lzr_mongodb_get_payload_length(ProbeTarget *target) {
    return sizeof(lzr_mongodb_payload) - 1;
}

static unsigned lzr_mongodb_handle_reponse(unsigned th_idx, ProbeTarget *target,
                                           const unsigned char *px,
                                           unsigned sizeof_px, OutItem *item) {
    if (safe_memmem(px, sizeof_px, "maxBsonObjectSize",
                    strlen("maxBsonObjectSize")) &&
        safe_memmem(px, sizeof_px, "MongoDB", strlen("MongoDB"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "mongodb");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not mongodb");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

Probe LzrMongodbProbe = {
    .name       = "lzr-mongodb",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc = "LzrMongodb Probe sends a mongodb probe and identifies mongodb "
            "service.",

    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &lzr_mongodb_make_payload,
    .get_payload_length_cb = &lzr_mongodb_get_payload_length,
    .handle_response_cb    = &lzr_mongodb_handle_reponse,
    .close_cb              = &probe_close_nothing,
};
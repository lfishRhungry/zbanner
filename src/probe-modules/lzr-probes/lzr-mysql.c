#include "../probe-modules.h"

#include <string.h>
#include <time.h>

#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrMysqlProbe;

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/9420b4a3-eb9f-4f5e-90bd-3160444aa5a7
static char lzr_mysql_payload[] = "\x20\x00\x00\x01\x00\x08\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00";

static size_t lzr_mysql_make_payload(ProbeTarget   *target,
                                     unsigned char *payload_buf) {
    memcpy(payload_buf, lzr_mysql_payload, sizeof(lzr_mysql_payload) - 1);
    return sizeof(lzr_mysql_payload) - 1;
}

static size_t lzr_mysql_get_payload_length(ProbeTarget *target) {
    return sizeof(lzr_mysql_payload) - 1;
}

static unsigned lzr_mysql_handle_reponse(unsigned th_idx, ProbeTarget *target,
                                         const unsigned char *px,
                                         unsigned sizeof_px, OutItem *item) {
    if (sizeof_px >= 49 && px[3] == 0x00 && px[4] == 0x0a) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "mysql");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not mysql");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

Probe LzrMysqlProbe = {
    .name       = "lzr-mysql",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc = "LzrMysql Probe sends an MYSQL probe and identifies MYSQL service.",

    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &lzr_mysql_make_payload,
    .get_payload_length_cb = &lzr_mysql_get_payload_length,
    .handle_response_cb    = &lzr_mysql_handle_reponse,
    .close_cb              = &probe_close_nothing,
};
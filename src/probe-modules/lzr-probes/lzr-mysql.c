#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrMysqlProbe;

//https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/9420b4a3-eb9f-4f5e-90bd-3160444aa5a7
static char lzr_mysql_payload[] =
"\x20\x00\x00\x01\x00\x08\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00";

static size_t
lzr_mysql_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_mysql_payload, sizeof(lzr_mysql_payload)-1);
    return sizeof(lzr_mysql_payload)-1;
}

static size_t
lzr_mysql_get_payload_length(struct ProbeTarget *target)
{
    return sizeof(lzr_mysql_payload)-1;
}

static unsigned
lzr_mysql_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not mysql");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }

    if (sizeof_px>=49 && px[3]==0x00 && px[4]==0x0a) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "mysql");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not mysql");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

struct ProbeModule LzrMysqlProbe = {
    .name       = "lzr-mysql",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrMysql Probe sends an MYSQL probe and identifies MYSQL service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_mysql_make_payload,
    .get_payload_length_cb                   = &lzr_mysql_get_payload_length,
    .validate_response_cb                    = NULL,
    .handle_response_cb                      = &lzr_mysql_handle_reponse,
    .close_cb                                = &probe_close_nothing,
};
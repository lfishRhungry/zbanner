#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrMssqlProbe;

//https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/9420b4a3-eb9f-4f5e-90bd-3160444aa5a7
static char lzr_mssql_payload[] =
"\x12\x01\x00\x2f\x00\x00\x02\x00\x00\x00\x1a\x00\x06"
"\x01\x00\x02\x00\x01\x02\x00\x21\x00\x01\x03\x00\x22"
"\x00\x04\x04\x00\x26\x00\x01\xff\x00\x00\x00\x00\x00"
"\x00\x01\x00\x00\x00\x00\x00\x00";

static size_t
lzr_mssql_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_mssql_payload, sizeof(lzr_mssql_payload)-1);
    return sizeof(lzr_mssql_payload)-1;
}

static size_t
lzr_mssql_get_payload_length(struct ProbeTarget *target)
{
    return sizeof(lzr_mssql_payload)-1;
}

static int
lzr_mssql_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not mssql");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }

    if (sizeof_px>=6 && px[0]==0x04 && px[1]==0x01) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "mssql");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not mssql");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

struct ProbeModule LzrMssqlProbe = {
    .name       = "lzr-mssql",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrMssql Probe sends an MSSQL probe and identifies MSSQL service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_mssql_make_payload,
    .get_payload_length_cb                   = &lzr_mssql_get_payload_length,
    .validate_response_cb                    = NULL,
    .handle_response_cb                      = &lzr_mssql_handle_reponse,
    .close_cb                                = &probe_close_nothing,
};
#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrRtspProbe;

static char lzr_rtsp_payload[] =
"OPTIONS / RTSP/1.0\r\n\r\n";


static size_t
lzr_rtsp_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_rtsp_payload, strlen(lzr_rtsp_payload));
    return strlen(lzr_rtsp_payload);
}

static size_t
lzr_rtsp_get_payload_length(struct ProbeTarget *target)
{
    return strlen(lzr_rtsp_payload);
}

static unsigned
lzr_rtsp_handle_reponse(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{

    if (safe_memmem(px, sizeof_px, "RTSP", strlen("RTSP"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "rtsp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not rtsp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_rtsp_handle_timeout(struct ProbeTarget *target, struct OutputItem *item)
{
    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not rtsp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

struct ProbeModule LzrRtspProbe = {
    .name       = "lzr-rtsp",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrRtsp Probe sends an RTSP probe and identifies RTSP service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_rtsp_make_payload,
    .get_payload_length_cb                   = &lzr_rtsp_get_payload_length,
    .handle_response_cb                      = &lzr_rtsp_handle_reponse,
    .handle_timeout_cb                       = &lzr_rtsp_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
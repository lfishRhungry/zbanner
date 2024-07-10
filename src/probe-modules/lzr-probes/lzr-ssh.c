#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrSshProbe;

static char lzr_ssh_payload[] =
"SSH-2.0-Go\r\n";


static size_t
lzr_ssh_make_payload(
    ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_ssh_payload, strlen(lzr_ssh_payload));
    return strlen(lzr_ssh_payload);
}

static size_t
lzr_ssh_get_payload_length(ProbeTarget *target)
{
    return strlen(lzr_ssh_payload);
}

static unsigned
lzr_ssh_handle_reponse(
    unsigned th_idx,
    ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    OutItem *item)
{

    if (safe_memismem(px, sizeof_px, "ssh", strlen("ssh"))
        && !safe_memismem(px, sizeof_px, "not implemented", strlen("not implemented"))
        && !safe_memismem(px, sizeof_px, "bad", strlen("bad"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "ssh");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    if (safe_memismem(px, sizeof_px, "Protocol mismatch", strlen("Protocol mismatch"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "ssh");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    if (safe_memismem(px, sizeof_px, "MaxStartup", strlen("MaxStartup"))
        || safe_memismem(px, sizeof_px, "MaxSession", strlen("MaxSession"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "ssh");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not ssh");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_ssh_handle_timeout(ProbeTarget *target, OutItem *item)
{
    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not ssh");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

Probe LzrSshProbe = {
    .name       = "lzr-ssh",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrSsh Probe sends an SSH probe and identifies SSH service.",
    .init_cb                                 = &probe_init_nothing,
    .make_payload_cb                         = &lzr_ssh_make_payload,
    .get_payload_length_cb                   = &lzr_ssh_get_payload_length,
    .handle_response_cb                      = &lzr_ssh_handle_reponse,
    .handle_timeout_cb                       = &lzr_ssh_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
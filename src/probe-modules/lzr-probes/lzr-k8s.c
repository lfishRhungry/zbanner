#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrK8sProbe;

//question: baidu.com
static char lzr_k8s_payload[] =
"\x16\x03\x01\x00\x75\x01\x00\x00\x71\x03\x03"
/*32 bytes rand*/
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

"\x00\x00\x1a\xc0\x2f\xc0\x2b\xc0\x11\xc0\x07\xc0\x13\xc0\x09\xc0"
"\x14\xc0\x0a\x00\x05\x00\x2f\x00\x35\xc0\x12\x00\x0a\x01\x00\x00"
"\x2e\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x0a\x00\x08\x00\x06"
"\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00\x0d\x00\x0a"
"\x00\x08\x04\x01\x04\x03\x02\x01\x02\x03\xff\x01\x00\x01\x00"
;

static int lzr_k8s_global_init(const struct Xconf *xconf)
{
    /*fill the random bytes in payload*/
    unsigned r;
    srand((unsigned)time(NULL));
    char *p = lzr_k8s_payload + 11; /*Now it's Random in Handshake Protocol*/
    for (unsigned i=0; i<32/4; i++) {
        r    = rand();
        p[0] = (r >> 24) & 0xFF;
        p[1] = (r >> 16) & 0xFF;
        p[2] = (r >>  8) & 0xFF;
        p[3] = (r >>  0) & 0xFF;
        p   += 4;
    }

    return 1;
}

static size_t
lzr_k8s_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_k8s_payload, sizeof(lzr_k8s_payload)-1);
    return sizeof(lzr_k8s_payload)-1;
}

static size_t
lzr_k8s_get_payload_length(struct ProbeTarget *target)
{
    return sizeof(lzr_k8s_payload)-1;
}

static int
lzr_k8s_handle_reponse(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not k8s");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }

    if (safe_memmem(px, sizeof_px, "kubernetes", strlen("kubernetes"))) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "k8s");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "not k8s");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

    return 0;
}

struct ProbeModule LzrK8sProbe = {
    .name       = "lzr-k8s",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrK8s Probe sends a kubernetes probe and identifies kubernetes service.",
    .global_init_cb                          = &lzr_k8s_global_init,
    .make_payload_cb                         = &lzr_k8s_make_payload,
    .get_payload_length_cb                   = &lzr_k8s_get_payload_length,
    .validate_response_cb                    = NULL,
    .handle_response_cb                      = &lzr_k8s_handle_reponse,
    .close_cb                                = &probe_close_nothing,
};
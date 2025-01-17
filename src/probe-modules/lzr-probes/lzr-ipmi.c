#include "../probe-modules.h"

#include <string.h>

#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrIpmiProbe;

static char lzr_ipmi_payload[] = "\x06\x00\xff\x07\x00\x00\x00\x00"
                                 "\x00\x00\x00\x00\x00\x09\x20\x18"
                                 "\xc8\x81\x00\x38\x8e\x04\xb5";

static char lzr_ipmi_pos_detect_unkn[] = {0x00, 0x00, 0x00, 0x02, 0x09, 0x00,
                                          0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00};

static size_t lzr_ipmi_make_payload(ProbeTarget   *target,
                                    unsigned char *payload_buf) {
    memcpy(payload_buf, lzr_ipmi_payload, sizeof(lzr_ipmi_payload) - 1);
    return sizeof(lzr_ipmi_payload) - 1;
}

static size_t lzr_ipmi_get_payload_length(ProbeTarget *target) {
    return sizeof(lzr_ipmi_payload) - 1;
}

static unsigned lzr_ipmi_handle_reponse(unsigned th_idx, ProbeTarget *target,
                                        const unsigned char *px,
                                        unsigned sizeof_px, OutItem *item) {
    if (safe_bytes_equals(px, sizeof_px, lzr_ipmi_pos_detect_unkn,
                          sizeof(lzr_ipmi_pos_detect_unkn))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "ipmi");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    if (sizeof_px > 4) {
        if (px[0] == 0x06 && px[1] == 0x00 && px[2] == 0xff && px[3] == 0x07) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "ipmi");
            safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        }
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not ipmi");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

Probe LzrIpmiProbe = {
    .name       = "lzr-ipmi",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc = "LzrIpmi Probe sends an IPMI probe and identifies IPMI service.",

    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &lzr_ipmi_make_payload,
    .get_payload_length_cb = &lzr_ipmi_get_payload_length,
    .handle_response_cb    = &lzr_ipmi_handle_reponse,
    .close_cb              = &probe_close_nothing,
};
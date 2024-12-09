#include "../probe-modules.h"

#include <string.h>
#include <time.h>

#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrModbusProbe;

static char lzr_modbus_payload[] = {0x5a, 0x47, 0x00, 0x00, 0x00, 0x05,
                                    0x00, 0x2b, 0x0e, 0x01, 0x00};

static size_t lzr_modbus_make_payload(ProbeTarget   *target,
                                      unsigned char *payload_buf) {
    memcpy(payload_buf, lzr_modbus_payload, sizeof(lzr_modbus_payload));
    return sizeof(lzr_modbus_payload);
}

static size_t lzr_modbus_get_payload_length(ProbeTarget *target) {
    return sizeof(lzr_modbus_payload);
}

static unsigned lzr_modbus_handle_reponse(unsigned th_idx, ProbeTarget *target,
                                          const unsigned char *px,
                                          unsigned sizeof_px, OutItem *item) {
    if (sizeof_px >= 4 && safe_bytes_equals(px, sizeof_px, "\x5a\x47\x00\x00",
                                            sizeof("\x5a\x47\x00\x00") - 1)) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "modbus");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not modbus");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

Probe LzrModbusProbe = {
    .name       = "lzr-modbus",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrModbus Probe sends a modbus probe and identifies Modbus service.",

    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &lzr_modbus_make_payload,
    .get_payload_length_cb = &lzr_modbus_get_payload_length,
    .handle_response_cb    = &lzr_modbus_handle_reponse,
    .close_cb              = &probe_close_nothing,
};
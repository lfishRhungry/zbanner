#include <string.h>
#include <time.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern struct ProbeModule LzrMqttProbe;

static char lzr_mqtt_payload[] = {
    0x10,0x0F,0x00,0x04,0x4d,0x51,0x54,
    0x54,0x04,0x00,0x00,0x0a,0x00,0x03,
    0x4c,0x5a,0x52
};

static size_t
lzr_mqtt_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, lzr_mqtt_payload, sizeof(lzr_mqtt_payload));
    return sizeof(lzr_mqtt_payload);
}

static size_t
lzr_mqtt_get_payload_length(struct ProbeTarget *target)
{
    return sizeof(lzr_mqtt_payload);
}

static unsigned
lzr_mqtt_handle_reponse(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{

    if (sizeof_px==4 && px[0]==0x20 && px[3]>=0x00 && px[3]<=0x05) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "mqtt");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not mqtt");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

static unsigned
lzr_mqtt_handle_timeout(struct ProbeTarget *target, struct OutputItem *item)
{
    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not mqtt");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

struct ProbeModule LzrMqttProbe = {
    .name       = "lzr-mqtt",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc =
        "LzrMqtt Probe sends an MQTT probe and identifies MQTT service.",
    .global_init_cb                          = &probe_global_init_nothing,
    .make_payload_cb                         = &lzr_mqtt_make_payload,
    .get_payload_length_cb                   = &lzr_mqtt_get_payload_length,
    .handle_response_cb                      = &lzr_mqtt_handle_reponse,
    .handle_timeout_cb                       = &lzr_mqtt_handle_timeout,
    .close_cb                                = &probe_close_nothing,
};
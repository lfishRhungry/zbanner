#include <stdio.h>

#include "probe-modules.h"
#include "../util/safe-string.h"
#include "../proto/proto-jarm.h"
#include "../util/logger.h"

static struct JarmConfig jc_list[] = {
    {
        .version         = TLS1_2_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_FORWARD,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_1_2_SUPPORT,
        .ext_order       = ExtOrder_REVERSE,
    },
    {
        .version         = TLS1_2_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_REVERSE,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_1_2_SUPPORT,
        .ext_order       = ExtOrder_FORWARD,
    },
    {
        .version         = TLS1_2_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_TOP_HALF,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_NO_SUPPORT,
        .ext_order       = ExtOrder_FORWARD,
    },
    {
        .version         = TLS1_2_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_BOTTOM_HALF,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_RARE,
        .support_ver_ext = SupportVerExt_NO_SUPPORT,
        .ext_order       = ExtOrder_FORWARD,
    },
    {
        .version         = TLS1_2_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_MIDDLE_OUT,
        .grease_use      = GreaseUse_YES,
        .alpn_use        = AlpnUse_RARE,
        .support_ver_ext = SupportVerExt_NO_SUPPORT,
        .ext_order       = ExtOrder_REVERSE,
    },
    {
        .version         = TLS1_1_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_FORWARD,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_NO_SUPPORT,
        .ext_order       = ExtOrder_FORWARD,
    },
    {
        .version         = TLS1_3_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_FORWARD,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_1_3_SUPPORT,
        .ext_order       = ExtOrder_REVERSE,
    },
    {
        .version         = TLS1_3_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_REVERSE,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_1_3_SUPPORT,
        .ext_order       = ExtOrder_FORWARD,
    },
    {
        .version         = TLS1_3_VERSION,
        .cipher_list     = CipherList_NO_1_3,
        .cipher_order    = CipherOrder_FORWARD,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_1_3_SUPPORT,
        .ext_order       = ExtOrder_FORWARD,
    },
    {
        .version         = TLS1_3_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_MIDDLE_OUT,
        .grease_use      = GreaseUse_YES,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_1_3_SUPPORT,
        .ext_order       = ExtOrder_REVERSE,
    },
};

/******************************************************************/

/*for x-refer*/
extern struct ProbeModule JarmProbe;

static size_t
jarm_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    if (target->index >= JarmProbe.multi_num)
        return 0;

    struct JarmConfig jc = jc_list[target->index];
    jc.servername        = ipaddress_fmt(target->ip_them).string;
    jc.dst_port          = target->port_them;

    return jarm_create_ch(&jc, payload_buf, PROBE_PAYLOAD_MAX_LEN);
}

size_t
jarm_get_payload_length(struct ProbeTarget *target)
{
    if (target->index >= JarmProbe.multi_num)
        return 0;

    struct JarmConfig jc = jc_list[target->index];
    jc.servername        = ipaddress_fmt(target->ip_them).string;
    jc.dst_port          = target->port_them;
    unsigned char buf[TLS_CLIENTHELLO_MAX_LEN];

    return jarm_create_ch(&jc, buf, TLS_CLIENTHELLO_MAX_LEN);
}

int
jarm_handle_response(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    /*handle timeout*/
    if (sizeof_px == 0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "no jarm");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "timeout");
        snprintf(item->report, OUTPUT_RPT_LEN, "JARM[%d]", target->index);
        return 0;
    }
    /**
     * The min length for ALERT
     * eg. \x15\x03\x01\x00\x02\x02
     * */
    if (sizeof_px < 7) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "no jarm");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not tls");
        return 0;
    }

    /*Just ALERT or HANDSHAKE are valid*/
    if (px[0]==TLS_RECORD_CONTENT_TYPE_ALERT
        || px[0]==TLS_RECORD_CONTENT_TYPE_HANDSHAKE) {
        /*Validate the VERSION field*/
        if (px[1]==0x03) {
            if (px[2]==0x00 || px[2]==0x01 || px[2]==0x02 || px[2]==0x03) {
                item->level = Output_SUCCESS;
                safe_strcpy(item->classification, OUTPUT_CLS_LEN, "jarmed");
                safe_strcpy(item->reason, OUTPUT_RSN_LEN, "tls banner");
                snprintf(item->report, OUTPUT_RPT_LEN, "JARM[%d]", target->index);
                return 1;
            }
        }
    }

    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "no jarm");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not tls");
    return 0;
}

struct ProbeModule JarmProbe = {
    .name       = "jarm",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_AfterHandle,
    .multi_num  = 10,
    .params     = NULL,
    .desc =
        "Jarm Probe sends 10 various TLS ClientHello probes in total if the first "
        "response represents the target port is running TLS protocol. Results can "
        "be analyzed to get JARM fingerprint of the target TLS stack for different "
        "purposes.",
    .global_init_cb                        = &probe_global_init_nothing,
    .make_payload_cb                       = &jarm_make_payload,
    .get_payload_length_cb                 = &jarm_get_payload_length,
    .validate_response_cb                  = NULL,
    .handle_response_cb                    = &jarm_handle_response,
    .close_cb                              = &probe_close_nothing,
};
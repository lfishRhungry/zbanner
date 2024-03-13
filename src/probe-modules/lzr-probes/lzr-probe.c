#include <stdio.h>

#include "../probe-modules.h"
#include "../../util/mas-safefunc.h"

#define LZR_HANDSHAKE_NAME_LEN 20

/*
 * LZR Probe will use `handle_response_cb` of all subprobes(handshakes) listed here
 * to match the banner and identify its service automaticly.
 * 
 * Subprobes' names always start with 'lzr-', and could be used as a normal
 * ProbeModule. It reports what service it identified out and will report
 * nothong if no service identified.
 * 
 * When they specified as subprobes in LZR probe with `--probe-args`, we should
 * omit the 'lzr-' prefix like 'lzr-http' -> 'http'.
 * 
 * LZR probe uses specified subprobe to send payload, and matches all subprobes
 * for result reporting. It could reports more than one identified service type
 * or 'unknown' if nothing identified.
 * 
 * NOTE: While ProbeModule is as Subprobe of LZR, its init and close callback
 * funcs will never be called.
 */

extern struct ProbeModule LzrWaitProbe;
extern struct ProbeModule LzrHttpProbe;
extern struct ProbeModule LzrFtpProbe;
//! ADD NEW LZR SUBPROBES(HANDSHAKES) HERE
//! ALSO ADD TO stateless-probes.c IF NEEDED



static struct ProbeModule *lzr_handshakes[] = {
    &LzrWaitProbe,
    &LzrHttpProbe,
    &LzrFtpProbe,
    //! ADD NEW LZR SUBPROBES(HANDSHAKES) HERE
    //! ALSO ADD TO probe-modules.c IF NEEDED
};

/******************************************************************/

/*for x-refer*/
extern struct ProbeModule LzrProbe;

struct LzrConf {
    struct ProbeModule *handshake;
};

static struct LzrConf lzr_conf = {0};

static int SET_handshake(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    char subprobe_name[LZR_HANDSHAKE_NAME_LEN] = "lzr-";
    memcpy(subprobe_name+strlen(subprobe_name), value, strlen(value));

    lzr_conf.handshake = get_probe_module_by_name(subprobe_name);

    if (lzr_conf.handshake == NULL) {
        fprintf(stderr, "[-] Invalid name of handshake for lzr.\n");
        return CONF_ERR;
    }

    return CONF_OK;
}

static struct ConfigParameter lzr_parameters[] = {
    {
        "handshake",
        SET_handshake,
        0,
        {"subprobe", "handshakes", "subprobes", 0},
        "Specifies a handshake(subprobe) to send probe."
    },

    {0}
};

static int
lzr_global_init(const void * xconf)
{
    /*Use LzrWait if no subprobe specified*/
    if (!lzr_conf.handshake) {
        lzr_conf.handshake = &LzrWaitProbe;
        fprintf(stderr, "[-] Use default LzrWait as handshake of LzrProbe "
            "because no handshake was specified by --handshake.\n");
    }

    LzrProbe.make_payload_cb = lzr_conf.handshake->make_payload_cb;
    LzrProbe.get_payload_length_cb = lzr_conf.handshake->get_payload_length_cb;

    return 1;
}

static int
lzr_handle_response(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }
    /**
     * I think it is long enough.
     * Some one has time to make it safe?
     * However I am tired while coding there.
    */
    char *rpt_idx = item->report;

    /**
     * strcat every lzr subprobes match result
     * print results just like lzr:
     *     pop3-smtp-http
    */
    for (size_t i=0; i<sizeof(lzr_handshakes)/sizeof(struct ProbeModule*); i++) {
        lzr_handshakes[i]->handle_response_cb(
            target, px, sizeof_px, item);

        if (item->level==Output_SUCCESS) {
            safe_strcpy(rpt_idx,
                OUTPUT_RPT_LEN-(rpt_idx-item->report), item->classification);

            for (;*rpt_idx!='\0';rpt_idx++) {}

            *rpt_idx = '-';
            rpt_idx++;
        }
    }

    if (rpt_idx==item->report) {
        /*got nothing*/
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");
    } else {
        /* remove last '-' */
        *(rpt_idx-1) = '\0';

        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "identified");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
    }

    return 0;
}

struct ProbeModule LzrProbe = {
    .name       = "lzr",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = lzr_parameters,
    .desc =
        "LZR Probe is an implement of service identification of LZR. It sends a "
        "specified LZR handshake(subprobe) and try to match with all LZR handshakes "
        "with `handle_reponse_cb`.",
    .global_init_cb                        = &lzr_global_init,
    .validate_response_cb                  = NULL,
    .handle_response_cb                    = &lzr_handle_response,
    .close_cb                              = &probe_close_nothing,
    // `make_payload_cb` will be set dynamicly in lzr_global_init.
    // `get_payload_length_cb` will be set dynamicly in lzr_global_init.
};
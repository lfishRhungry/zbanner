#include <stdio.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util/safe-string.h"
#include "../../util/fine-malloc.h"

#define LZR_HANDSHAKE_NAME_LEN 20

/*
 * LZR Probe will use `handle_response_cb` of all subprobes(handshakes) listed here
 * to match the banner and identify its service automaticly.
 * 
 * Subprobes' names always start with 'lzr-', and could be used as a normal
 * ProbeModule.
 * 
 * When they specified as subprobes in LZR probe with `--probe-args`, we should
 * omit the 'lzr-' prefix like 'lzr-http' -> 'http'.
 * 
 * LZR probe uses specified subprobe to send payload, and matches all subprobes
 * for result reporting. It could reports more than one identified service type
 * or 'unknown' if nothing identified.
 * 
 * NOTE: While ProbeModule is as Subprobe of LZR, its `params` will not be
 * configured.
 */

//! ADD NEW LZR SUBPROBES(HANDSHAKES) HERE
//! ALSO ADD TO stateless-probes.c IF NEEDED
extern struct ProbeModule LzrHttpProbe;
extern struct ProbeModule LzrTlsProbe;
extern struct ProbeModule LzrFtpProbe;
extern struct ProbeModule LzrPop3Probe;
extern struct ProbeModule LzrImapProbe;
extern struct ProbeModule LzrMqttProbe;
extern struct ProbeModule LzrAmqpProbe;
extern struct ProbeModule LzrMysqlProbe;
extern struct ProbeModule LzrMongodbProbe;
extern struct ProbeModule LzrPostgresProbe;
extern struct ProbeModule LzrMssqlProbe;
extern struct ProbeModule LzrOracleProbe;
extern struct ProbeModule LzrK8sProbe;
extern struct ProbeModule LzrModbusProbe;
extern struct ProbeModule LzrPptpProbe;
extern struct ProbeModule LzrDnsProbe;
extern struct ProbeModule LzrIpmiProbe;
extern struct ProbeModule LzrDnp3Probe;
extern struct ProbeModule LzrFoxProbe;
extern struct ProbeModule LzrMemcachedAsciiProbe;
extern struct ProbeModule LzrMemcachedBinaryProbe;
extern struct ProbeModule LzrIppProbe;
extern struct ProbeModule LzrWaitProbe;
extern struct ProbeModule LzrNewlinesProbe;
extern struct ProbeModule LzrNewlines50Probe;



//! ADD NEW LZR SUBPROBES(HANDSHAKES) HERE
//! ALSO ADD TO probe-modules.c IF NEEDED
static struct ProbeModule *lzr_handshakes[] = {
    &LzrHttpProbe,
    &LzrTlsProbe,
    &LzrFtpProbe,
    &LzrPop3Probe,
    &LzrImapProbe,
    &LzrAmqpProbe,
    &LzrMysqlProbe,
    &LzrMongodbProbe,
    &LzrPostgresProbe,
    &LzrMssqlProbe,
    &LzrOracleProbe,
    &LzrK8sProbe,
    &LzrModbusProbe,
    &LzrPptpProbe,
    &LzrDnsProbe,
    &LzrIpmiProbe,
    &LzrMqttProbe,
    &LzrDnp3Probe,
    &LzrFoxProbe,
    &LzrMemcachedAsciiProbe,
    &LzrMemcachedBinaryProbe,
    &LzrIppProbe,
    &LzrWaitProbe,
    &LzrNewlinesProbe,
    &LzrNewlines50Probe,
};

/******************************************************************/

/*for x-refer*/
extern struct ProbeModule LzrProbe;

struct LzrConf {
    struct ProbeModule **handshake;
    unsigned hs_count;
    unsigned force_all_handshakes:1;
    unsigned force_all_match:1;
};

static struct LzrConf lzr_conf = {0};

static int SET_force_all_match(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    lzr_conf.force_all_match = parseBoolean(value);

    return CONF_OK;
}

static int SET_force_all_handshake(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    lzr_conf.force_all_handshakes = parseBoolean(value);

    return CONF_OK;
}

static int SET_handshake(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    char  *str     = STRDUP(value);
    size_t str_len = strlen(str);
    if (str_len == 0) {
        fprintf(stderr, "[-] Invalid name of handshake for lzr.\n");
        return CONF_ERR;
    }

    size_t hs_count = 0;
    char  *p        = str;
    for (;p-str < str_len;p++) {
        if (*p!=' ' && *p!=',') {
            hs_count++;
        }
        for (;p-str<str_len && *p!=' ' && *p!=',';p++){}
        /*create C string*/
        *p = '\0';
    }

    lzr_conf.hs_count  = hs_count;
    lzr_conf.handshake = MALLOC(sizeof(struct ProbeModule *)*hs_count);
    size_t hs_index = 0;
    p               = str;
    for (;p-str < str_len;p++) {
        if (*p!='\0') {

            char hs_name[LZR_HANDSHAKE_NAME_LEN] = "lzr-";
            safe_strcpy(hs_name+strlen(hs_name), LZR_HANDSHAKE_NAME_LEN-4, p);
            lzr_conf.handshake[hs_index] = get_probe_module_by_name(hs_name);

            if (lzr_conf.handshake[hs_index] == NULL) {
                fprintf(stderr, "[-] Invalid name of handshake for lzr.\n");
                free(str);
                return CONF_ERR;
            }

            hs_index++;
        }
        for (;p-str<str_len && *p!='\0';p++){}
    }

    free(str);

    return CONF_OK;
}

static struct ConfigParameter lzr_parameters[] = {
    {
        "handshake",
        SET_handshake,
        0,
        {"subprobe", "handshakes", "subprobes", 0},
        "Specifies handshakes(subprobes) for probe sending. Handshake names are "
        "splitted by comma like `--handshake http,tls`."
    },
    {
        "force-all-match",
        SET_force_all_match,
        F_BOOL,
        {"all-match", 0},
        "Complete all matching process even if identified. This might get multi- "
        "results."
    },
    {
        "force-all-handshakes",
        SET_force_all_handshake,
        F_BOOL,
        {"force-all-handshake", "all-handshake", "all-handshakes", 0},
        "Complete all specified handshakes even if identified. This could make "
        "weird count of results."
    },

    {0}
};

static int
lzr_global_init(const struct Xconf *xconf)
{
    /*Use LzrWait if no subprobe specified*/
    if (!lzr_conf.handshake) {
        lzr_conf.handshake    = MALLOC(sizeof(struct ProbeModule *));
        lzr_conf.handshake[0] = &LzrHttpProbe;
        lzr_conf.hs_count     = 1;
        fprintf(stderr, "[-] Use default LzrHttpProbe(http) as handshake of LzrProbe "
            "because no handshake was specified by --handshake.\n");
    }

    /*do init for all handshakes*/
    for (unsigned i=0; i<lzr_conf.hs_count; i++) {
        if (!lzr_conf.handshake[i]->global_init_cb(xconf)) {
            fprintf(stderr, "FAIL: Handshake [%s] initiating error in LzrProbe.\n",
                lzr_conf.handshake[i]->name);
            return 0;
        }
    }

    return 1;
}

static size_t
lzr_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    return lzr_conf.handshake[target->index]->make_payload_cb(target, payload_buf);
}

static size_t
lzr_get_payload_length(struct ProbeTarget *target)
{
    return lzr_conf.handshake[target->index]->get_payload_length_cb(target);
}

static int
lzr_handle_response(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        snprintf(item->report, OUTPUT_RPT_LEN, "[handshake: %s]",
            lzr_conf.handshake[target->index]->name);
        /*set all unmatching as failure*/
        item->level = Output_FAILURE;
        /*last handshake*/
        if (target->index != lzr_conf.hs_count-1) {
            return target->index+2;
        } else {
            return 0;
        }
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

            if (!lzr_conf.force_all_match)
                break;
        }
    }

    if (rpt_idx==item->report) {
        /*got nothing*/
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");
        snprintf(item->report, OUTPUT_RPT_LEN, "[handshake: %s]",
            lzr_conf.handshake[target->index]->name);
        /*set all unmatching as failure*/
        item->level = Output_FAILURE;
        /*last handshake*/
        if (target->index != lzr_conf.hs_count-1) {
            return target->index+2;
        } else {
            return 0;
        }
    } else {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "identified");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        snprintf(rpt_idx-1, OUTPUT_RPT_LEN-(rpt_idx-item->report)+1, " [handshake: %s]",
            lzr_conf.handshake[target->index]->name);

        if (lzr_conf.force_all_handshakes && target->index != lzr_conf.hs_count-1) {
            return target->index+2;
        }
    }

    return 0;
}

void lzr_close()
{
    /*close for every handshake*/
    /*do init for all handshakes*/
    for (unsigned i=0; i<lzr_conf.hs_count; i++)
        lzr_conf.handshake[i]->close_cb();
 
    free(lzr_conf.handshake);
}

struct ProbeModule LzrProbe = {
    .name       = "lzr",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_DynamicNext,
    .multi_num  = 1,
    .params     = lzr_parameters,
    .desc =
        "LzrProbe is an implementation of LZR service identifier of LZR in "
        XTATE_FIRST_UPPER_NAME". It sends a serias specified LZR handshakes"
        "(subprobes) until identified the service by matching responsed data "
        "with all LZR handshakes.\n"
        "I suggest you to specify `--timeout` parameter because LzrProbe performs"
        " better by recognizing the status of non-responsing.",
    .global_init_cb                        = &lzr_global_init,
    .make_payload_cb                       = &lzr_make_payload,
    .get_payload_length_cb                 = &lzr_get_payload_length,
    .validate_response_cb                  = NULL,
    .handle_response_cb                    = &lzr_handle_response,
    .close_cb                              = &lzr_close,
};
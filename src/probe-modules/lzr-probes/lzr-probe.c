#include <stdio.h>

#include "../probe-modules.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"
#include "../../util-data/fine-malloc.h"

#define LZR_HANDSHAKE_NAME_LEN 20

/*
 * LZR Probe will use `handle_response_cb` of all subprobes(handshakes) listed here
 * to match the banner and identify its service automaticly.
 * 
 * Subprobes' names always start with 'lzr-' and could be used as a normal
 * ProbeModule. Subprobes set classification of result to the service name and
 * output level to success if it identified successfully.
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
extern struct ProbeModule LzrSmtpProbe;
extern struct ProbeModule LzrSshProbe;
extern struct ProbeModule LzrSocks5Probe;
extern struct ProbeModule LzrTelnetProbe;
extern struct ProbeModule LzrFixProbe;
extern struct ProbeModule LzrSmbProbe;
extern struct ProbeModule LzrMqttProbe;
extern struct ProbeModule LzrAmqpProbe;
extern struct ProbeModule LzrMysqlProbe;
extern struct ProbeModule LzrMongodbProbe;
extern struct ProbeModule LzrRedisProbe;
extern struct ProbeModule LzrPostgresProbe;
extern struct ProbeModule LzrMssqlProbe;
extern struct ProbeModule LzrOracleProbe;
extern struct ProbeModule LzrRdpProbe;
extern struct ProbeModule LzrX11Probe;
extern struct ProbeModule LzrVncProbe;
extern struct ProbeModule LzrK8sProbe;
extern struct ProbeModule LzrRtspProbe;
extern struct ProbeModule LzrModbusProbe;
extern struct ProbeModule LzrSiemensProbe;
extern struct ProbeModule LzrBgpProbe;
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
    &LzrSmtpProbe,
    &LzrSshProbe,
    &LzrSocks5Probe,
    &LzrTelnetProbe,
    &LzrFixProbe,
    &LzrSmbProbe,
    &LzrAmqpProbe,
    &LzrMysqlProbe,
    &LzrMongodbProbe,
    &LzrRedisProbe,
    &LzrPostgresProbe,
    &LzrMssqlProbe,
    &LzrOracleProbe,
    &LzrRdpProbe,
    &LzrX11Probe,
    &LzrVncProbe,
    &LzrK8sProbe,
    &LzrRtspProbe,
    &LzrModbusProbe,
    &LzrSiemensProbe,
    &LzrBgpProbe,
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
    unsigned banner_if_fail:1;
    unsigned banner:1;
};

static struct LzrConf lzr_conf = {0};

static enum ConfigRes SET_show_banner(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    lzr_conf.banner = parseBoolean(value);

    return Conf_OK;
}

static enum ConfigRes SET_banner_if_fail(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    lzr_conf.banner_if_fail = parseBoolean(value);

    return Conf_OK;
}

static enum ConfigRes SET_force_all_match(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    lzr_conf.force_all_match = parseBoolean(value);

    return Conf_OK;
}

static enum ConfigRes SET_force_all_handshake(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    lzr_conf.force_all_handshakes = parseBoolean(value);

    return Conf_OK;
}

static enum ConfigRes SET_handshake(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    char  *str     = STRDUP(value);
    size_t str_len = strlen(str);
    if (str_len == 0) {
        LOG(LEVEL_ERROR, "[-] Invalid name of handshake for lzr.\n");
        return Conf_ERR;
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
                LOG(LEVEL_ERROR, "[-] Invalid name of handshake for lzr.\n");
                free(str);
                return Conf_ERR;
            }

            hs_index++;
        }
        for (;p-str<str_len && *p!='\0';p++){}
    }

    free(str);

    return Conf_OK;
}

static struct ConfigParam lzr_parameters[] = {
    {
        "handshake",
        SET_handshake,
        Type_NONE,
        {"subprobe", "handshakes", "subprobes", 0},
        "Specifies handshakes(subprobes) for probe sending. Handshake names are "
        "splitted by comma like `--handshake http,tls`."
    },
    {
        "force-all-match",
        SET_force_all_match,
        Type_BOOL,
        {"all-match", 0},
        "Complete all matching process even if identified. This might get multi- "
        "results."
    },
    {
        "force-all-handshakes",
        SET_force_all_handshake,
        Type_BOOL,
        {"force-all-handshake", "all-handshake", "all-handshakes", 0},
        "Complete all specified handshakes even if identified. This could make "
        "weird count of results."
    },
    {
        "banner",
        SET_show_banner,
        Type_BOOL,
        {0},
        "Show normalized banner in results."
    },
    {
        "banner-if-fail",
        SET_banner_if_fail,
        Type_BOOL,
        {"banner-fail", "fail-banner", 0},
        "Show normalized banner in results if failed to identify."
    },

    {0}
};

static bool
lzr_global_init(const struct Xconf *xconf)
{
    /*Use LzrWait if no subprobe specified*/
    if (!lzr_conf.handshake) {
        lzr_conf.handshake    = MALLOC(sizeof(struct ProbeModule *));
        lzr_conf.handshake[0] = &LzrHttpProbe;
        lzr_conf.hs_count     = 1;
        LOG(LEVEL_HINT, "[-] Use default LzrHttpProbe(http) as handshake of LzrProbe "
            "because no handshake was specified by --handshake.\n");
    }

    /*do init for all handshakes*/
    for (unsigned i=0; i<lzr_conf.hs_count; i++) {
        if (!lzr_conf.handshake[i]->global_init_cb(xconf)) {
            LOG(LEVEL_ERROR, "FAIL: Handshake [%s] initiating error in LzrProbe.\n",
                lzr_conf.handshake[i]->name);
            return false;
        }
    }

    return true;
}

static size_t
lzr_make_payload(struct ProbeTarget *target, unsigned char *payload_buf)
{
    return lzr_conf.handshake[target->index]->make_payload_cb(target, payload_buf);
}

static size_t
lzr_get_payload_length(struct ProbeTarget *target)
{
    if (target->index < lzr_conf.hs_count)
        return lzr_conf.handshake[target->index]->get_payload_length_cb(target);

    return 0;
}

static unsigned
lzr_handle_response(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    /**
     * print results just like lzr:
     *     pop3-smtp-http
    */
    bool identified = false;
    struct DataLink *res_link;
    res_link = dach_new_link(&item->report, "result", 1, false);

    size_t i = 0;
    for (; i<ARRAY_SIZE(lzr_handshakes); i++) {
        lzr_handshakes[i]->handle_response_cb(
            th_idx, target, px, sizeof_px, item);

        if (item->level==Output_SUCCESS) {
            res_link = dach_append_by_link(res_link, item->classification,
                strlen(item->classification));
            identified = true;
            break;
        }
    }

    if (lzr_conf.force_all_match) {
        for (++i; i<ARRAY_SIZE(lzr_handshakes); i++) {
            lzr_handshakes[i]->handle_response_cb(
                th_idx, target, px, sizeof_px, item);

            if (item->level==Output_SUCCESS) {
                res_link = dach_printf_by_link(res_link, "-%s", item->classification);
            }
        }
    }

    dach_append(&item->report, "handshake",
        lzr_conf.handshake[target->index]->name,
        strlen(lzr_conf.handshake[target->index]->name));

    if (identified) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "identified");
        safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "matched");

        if (lzr_conf.banner) {
            dach_append_normalized(&item->report, "banner", px, sizeof_px);
        }

        if (lzr_conf.force_all_handshakes && target->index != lzr_conf.hs_count-1) {
            return target->index+2;
        }
    } else {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "unknown");
        safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "not matched");
        dach_del_by_link(&item->report, res_link);

        if (lzr_conf.banner_if_fail || lzr_conf.banner) {
            dach_append_normalized(&item->report, "banner", px, sizeof_px);
        }

        /*last handshake*/
        if (target->index != lzr_conf.hs_count-1 && lzr_conf.force_all_handshakes) {
            return target->index+2;
        } else {
            return 0;
        }
    }

    return 0;
}

static unsigned
lzr_handle_timeout(struct ProbeTarget *target, struct OutputItem *item)
{
    safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "unknown");
    safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "no response");
    dach_append(&item->report, "handshake",
        lzr_conf.handshake[target->index]->name,
        strlen(lzr_conf.handshake[target->index]->name));
    /**
     * Set last unmatching as failure in normal mode.
     * Or all unmatching as failure if force-all-handshakes
     * */
    if (target->index == lzr_conf.hs_count-1 || lzr_conf.force_all_handshakes)
        item->level = Output_FAILURE;
    /*last handshake*/
    if (target->index != lzr_conf.hs_count-1) {
        return target->index+2;
    } else {
        return 0;
    }
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
        "LzrProbe is an implementation of LZR( a service identifier) in "
        XTATE_FIRST_UPPER_NAME". It sends a serias specified LZR handshakes"
        "(subprobes) until identified the service by matching responsed data "
        "with all LZR handshakes.\n"
        "I suggest you to specify `--timeout` parameter because LzrProbe performs"
        " better by recognizing the status of non-responsing.\n"
        "NOTE1: Recommended optimal handshake order by LZR paper:\n"
        "1.  wait\n"
        "2.  tls\n"
        "3.  http\n"
        "4.  dns\n"
        "5.  pptp\n"
        "NOTE2: I had fixed some matching bugs and errors from original LZR and "
        "added more useful handshakes. So, enjoy it!",
    .global_init_cb                          = &lzr_global_init,
    .make_payload_cb                         = &lzr_make_payload,
    .get_payload_length_cb                   = &lzr_get_payload_length,
    .handle_response_cb                      = &lzr_handle_response,
    .handle_timeout_cb                       = &lzr_handle_timeout,
    .close_cb                                = &lzr_close,
};
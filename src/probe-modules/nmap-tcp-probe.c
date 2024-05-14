#ifndef NOT_FOUND_PCRE2

#include <string.h>

#include "probe-modules.h"
#include "../version.h"
#include "../util-out/logger.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../nmap/nmap-service.h"

/*for internal x-ref*/
extern struct ProbeModule NmapTcpProbe;

struct NmapTcpConf {
    struct NmapServiceProbeList *service_probes;
    char *                       probe_file;
    char *                       softmatch;
    unsigned                     rarity;
    unsigned                     no_port_limit:1;
};

static struct NmapTcpConf nmaptcp_conf = {0};


static enum Config_Res SET_no_port_limit(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    nmaptcp_conf.no_port_limit = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_softmatch(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (nmaptcp_conf.softmatch) {
        free(nmaptcp_conf.softmatch);
    }

    nmaptcp_conf.softmatch = STRDUP(value);
    return CONF_OK;
}

static enum Config_Res SET_probe_file(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (nmaptcp_conf.probe_file) {
        free(nmaptcp_conf.probe_file);
    }

    nmaptcp_conf.probe_file = STRDUP(value);
    return CONF_OK;
}

static enum Config_Res SET_rarity(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    unsigned rarity = parseBoolean(value);
    if (rarity < 1 || rarity > 9) {
        LOG(LEVEL_ERROR, "[-] NmapTcpProbe: rarity must be in range 1-9.\n");
        return CONF_ERR;
    }

    nmaptcp_conf.rarity = rarity;

    return CONF_OK;
}

static struct ConfigParam nmapservice_parameters[] = {
    {
        "probe-file",
        SET_probe_file,
        F_NONE,
        {"service-probe-file", "probes-file", 0},
        "Specifies nmap-service-probes file for probes loading."
    },
    {
        "rarity",
        SET_rarity,
        F_NONE,
        {"intensity", 0},
        "Specifies the intensity of nmap version scan. The lower-numbered probes"
        " are effective against a wide variety of common services, while the "
        "higher-numbered ones are rarely useful. The intensity must be between 1"
        " and 9. The default is 7."
    },
    {
        "softmatch",
        SET_softmatch,
        F_NONE,
        {0},
        "Specifies what service has been softmatched for target ports before, so "
        "NmapTcpProbe could use more accurate probes to reduce cost and just do "
        "hard matching.\n"
        "NOTE: This param exists because the strategy of Nmap services matching "
        "cannot be implemented completely in stateless mode."
    },
    {
        "no-port-limit",
        SET_no_port_limit,
        F_NUMABLE,
        {0},
        "Switch on this param to release limitation of port ranges in probes of "
        "nmap-service-probes file."
    },

    {0}
};

static bool
nmaptcp_global_init(const struct Xconf *xconf)
{
    /*Use LzrWait if no subprobe specified*/
    if (!nmaptcp_conf.probe_file) {
        LOG(LEVEL_ERROR, "[-] No nmap-service-probes file specified.\n");
        return false;
    }
    nmaptcp_conf.service_probes =
        nmapservice_read_file(nmaptcp_conf.probe_file);

    if (!nmaptcp_conf.service_probes) {
        LOG(LEVEL_ERROR, "[-] NmapTcpProbe: invalid nmap_service_probes file: %s\n",
            nmaptcp_conf.probe_file);
        return false;
    }

    if (!nmaptcp_conf.service_probes->count) {
        LOG(LEVEL_ERROR, "[-] NmapTcpProbe: no probe has been loaded from %s\n",
            nmaptcp_conf.probe_file);
        nmapservice_free(nmaptcp_conf.service_probes);
        return false;
    }

    nmapservice_match_compile(nmaptcp_conf.service_probes);
    LOG(LEVEL_HINT, "[hint] NmapTcpProbe: probes loaded and compiled.\n");

    nmapservice_link_fallback(nmaptcp_conf.service_probes);
    LOG(LEVEL_HINT, "[hint] NmapTcpProbe: probe fallbacks linked.\n");

    if (nmaptcp_conf.rarity == 0) {
        nmaptcp_conf.rarity = 7;
        LOG(LEVEL_HINT, "[hint] NmapTcpProbe: no rarity specified, use default 7.\n");
    }

    return true;
}

static void
nmaptcp_close()
{
    if (nmaptcp_conf.service_probes) {
        nmapservice_match_free(nmaptcp_conf.service_probes);
        LOG(LEVEL_INFO, "[hint] NmapTcpProbe: probes compilation freed.\n");

        nmapservice_free(nmaptcp_conf.service_probes);
        LOG(LEVEL_INFO, "[hint] NmapTcpProbe: probes freed.\n");

        nmaptcp_conf.service_probes = NULL;
    }

    if (nmaptcp_conf.probe_file) {
        free(nmaptcp_conf.probe_file);
        nmaptcp_conf.probe_file = NULL;
    }

    if (nmaptcp_conf.softmatch) {
        free(nmaptcp_conf.softmatch);
        nmaptcp_conf.softmatch = NULL;
    }
}

static size_t
nmaptcp_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf,
        nmaptcp_conf.service_probes->probes[target->index]->hellostring,
        nmaptcp_conf.service_probes->probes[target->index]->hellolength);

    return nmaptcp_conf.service_probes->probes[target->index]->hellolength;
}

static size_t
nmaptcp_get_payload_length(struct ProbeTarget *target)
{
    if (target->index >= nmaptcp_conf.service_probes->count)
        return 0;

    return nmaptcp_conf.service_probes->probes[target->index]->hellolength;
}

/**
 * I don't have good way to identify whether the response is from probe
 * sended after softmatched.
 * So we don't support sending probe again after softmatch and treat all tm-event
 * as not from probe after softmatch.
*/
unsigned
nmaptcp_handle_response(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    struct NmapServiceProbeList *list = nmaptcp_conf.service_probes;
    unsigned next_probe = 0;

    /**
     * no response
     * */
    if (sizeof_px==0) {
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        snprintf(item->report, OUTPUT_RPT_LEN, "[probe: %s]",
            list->probes[target->index]->name);

        /**
         * We have to check whether it is the last available probe.
         * */
        unsigned next_probe = nmapservice_next_probe_index(list, target->index,
            nmaptcp_conf.no_port_limit?0:target->port_them,
            nmaptcp_conf.rarity, NMAP_IPPROTO_TCP,
            nmaptcp_conf.softmatch);

        if (next_probe) {
            return next_probe+1;
        } else {
            /*last availabe probe*/
            item->level = Output_FAILURE;
            return 0;
        }
    }

    struct ServiceProbeMatch *match = nmapservice_match_service(list,
        target->index, px, sizeof_px,
        NMAP_IPPROTO_TCP, nmaptcp_conf.softmatch);

    if (match) {
        item->level = Output_SUCCESS;

        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "identified");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN,
            match->is_softmatch?"softmatch":"matched");
        int n = snprintf(item->report, OUTPUT_RPT_LEN, "[service: %s, line: %u",
            match->service, match->line);
        if (!match->is_softmatch&&match->versioninfo) {
            n += snprintf(item->report+n, OUTPUT_RPT_LEN-n, ", info: %s", match->versioninfo->value);
        }
        snprintf(item->report+n, OUTPUT_RPT_LEN-n, "]");

        return 0;
    }

    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");
    snprintf(item->report, OUTPUT_RPT_LEN, "[probe: %s]",
        list->probes[target->index]->name);

    /*fail to match or in softmatch mode, try to send next possible probe*/
    next_probe = nmapservice_next_probe_index(list, target->index,
        nmaptcp_conf.no_port_limit?0:target->port_them,
        nmaptcp_conf.rarity, NMAP_IPPROTO_TCP,
        nmaptcp_conf.softmatch);

    /*no more probe, treat it as failure*/
    if (!next_probe) {
        item->level = Output_FAILURE;
        return 0;
    }

    return next_probe+1;
}

struct ProbeModule NmapTcpProbe = {
    .name       = "nmap-tcp",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_DynamicNext,
    .multi_num  = 1,
    .params     = nmapservice_parameters,
    .desc =
        "NmapTcp Probe sends payloads from specified nmap-service-probes "
        "file and identifies service and version of target tcp port just like Nmap."
        " NmapService is an emulation of Nmap's service identification. Use"
        " `--probe-file` subparam to set nmap-service-probes file to load. Use "
        "timeout mode to handle no response correctly.\n"
        "NOTE1: No proper way to do complete matching after a softmatch now. "
        "Because we couldn't identify whether the response banner is from a probe"
        " after softmatch or not. So specify what softmatch service have been "
        "identified and scan these targets again to try to get accurate results.\n"
        "NOTE2: Some hardmatch in nmap-service-probes file need banners from 2 "
        "phases(from Hellowait and after probe sending) to match patterns. "
        "NmapTcp Probe cannot do this type of hard matching because stateless "
        "mechanism doesn't support \"Hello Wait\".\n"
        "Dependencies: PCRE2.",
    .global_init_cb                    = &nmaptcp_global_init,
    .make_payload_cb                   = &nmaptcp_make_payload,
    .get_payload_length_cb             = &nmaptcp_get_payload_length,
    .validate_response_cb              = NULL,
    .handle_response_cb                = &nmaptcp_handle_response,
    .close_cb                          = &nmaptcp_close,
};

#endif /*ifndef NOT_FOUND_PCRE2*/
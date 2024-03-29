#include <string.h>

#include "probe-modules.h"
#include "../util/logger.h"
#include "../util/fine-malloc.h"
#include "../util/safe-string.h"
#include "../nmap/nmap-service.h"

/*for internal x-ref*/
extern struct ProbeModule NmapServiceProbe;

struct NmapServiceConf {
    struct NmapServiceProbeList *service_probes;
    char *                       probe_file;
    unsigned                     rarity;
};

static struct NmapServiceConf nmapservice_conf = {0};


static int SET_probe_file(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (nmapservice_conf.probe_file) {
        free(nmapservice_conf.probe_file);
    }

    nmapservice_conf.probe_file = STRDUP(value);
    return CONF_OK;
}

static struct ConfigParameter nmapservice_parameters[] = {
    {
        "probe-file",
        SET_probe_file,
        0,
        {"service-probe-file", "probes-file", 0},
        "Specifies nmap-service-probes file for probes loading."
    },

    {0}
};

static int
nmapservice_global_init(const struct Xconf *xconf)
{
    /*Use LzrWait if no subprobe specified*/
    if (!nmapservice_conf.probe_file) {
        LOG(LEVEL_ERROR, "[-] No nmap-service-probes file specified.\n");
        return 0;
    }
    nmapservice_conf.service_probes =
        nmapservice_read_file(nmapservice_conf.probe_file);

    if (!nmapservice_conf.service_probes) {
        LOG(LEVEL_ERROR, "[-] NmapServiceProbe: invalid nmap_service_probes file: %s\n",
            nmapservice_conf.probe_file);
        return 0;
    }

    if (!nmapservice_conf.service_probes->count) {
        LOG(LEVEL_ERROR, "[-] NmapServiceProbe: no probe has been loaded from %s\n",
            nmapservice_conf.probe_file);
        nmapservice_free(nmapservice_conf.service_probes);
        return 0;
    }

    nmapservice_match_compile(nmapservice_conf.service_probes);
    LOG(LEVEL_INFO, "[hint] NmapServiceProbe: probes loaded and compiled.\n");

    nmapservice_link_fallback(nmapservice_conf.service_probes);
    LOG(LEVEL_INFO, "[hint] NmapServiceProbe: probe fallbacks linked.\n");

    if (nmapservice_conf.rarity == 0) {
        nmapservice_conf.rarity = 6;
        LOG(LEVEL_INFO, "[hint] NmapServiceProbe: no rarity specified, use default 6.\n");
    }

    return 1;
}

static void
nmapservice_close()
{
    if (nmapservice_conf.service_probes) {
        nmapservice_match_free(nmapservice_conf.service_probes);
        LOG(LEVEL_INFO, "[hint] NmapServiceProbe: probes compilation freed.\n");

        nmapservice_free(nmapservice_conf.service_probes);
        LOG(LEVEL_INFO, "[hint] NmapServiceProbe: probes freed.\n");

        nmapservice_conf.service_probes = NULL;
    }
}

static size_t
nmapservice_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf,
        nmapservice_conf.service_probes->probes[target->index]->hellostring,
        nmapservice_conf.service_probes->probes[target->index]->hellolength);

    return nmapservice_conf.service_probes->probes[target->index]->hellolength;
}

static size_t
nmapservice_get_payload_length(struct ProbeTarget *target)
{
    if (target->index >= nmapservice_conf.service_probes->count)
        return 0;

    return nmapservice_conf.service_probes->probes[target->index]->hellolength;
}

/**
 * I don't have good way to identify whether the response is from probe
 * after softmatch.
 * So we don't support sending probe again after softmatch and treat all tm-event
 * as not from probe after softmatch.
*/
int
nmapservice_handle_response(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    struct NmapServiceProbeList *probes = nmapservice_conf.service_probes;

    /**
     * no response
     * We do not send probe after softmatch, So this is a normal no response.
     * */
    if (sizeof_px==0) {
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        snprintf(item->report, OUTPUT_RPT_LEN, "[probe: %s]",
            probes->probes[target->index]->name);

        /**
         * We have to check whether it is the last available probe.
         * */
        unsigned next_probe = nmapservice_next_probe_index(probes,
            target->index, target->port_them,
            nmapservice_conf.rarity, NMAP_IPPROTO_TCP);

        if (next_probe) {
            return next_probe+1;
        } else {
            /*last availabe probe*/
            item->level = Output_FAILURE;
            return 0;
        }
    }

    struct ServiceProbeMatch *match = nmapservice_match_service(probes,
        target->index, px, sizeof_px, NMAP_IPPROTO_TCP);

    if (match) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "identified");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN,
            match->is_softmatch?"softmatch":"matched");
        snprintf(item->report, OUTPUT_RPT_LEN, "[probe: %s, service: %s]",
            probes->probes[target->index]->name, match->service);

        return 0;
    }

    /**
     * not matched.
     * Nmap's logic will stop sending new probe.
     * */
    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");
    snprintf(item->report, OUTPUT_RPT_LEN, "[probe: %s]",
        probes->probes[target->index]->name);

    return 0;
}

struct ProbeModule NmapServiceProbe = {
    .name       = "nmap-service",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_DynamicNext,
    .multi_num  = 1,
    .params     = nmapservice_parameters,
    .desc =
        "GetRequest Probe sends target port a simple HTTP Get request:\n"
        "    `GET / HTTP/1.0\\r\\n\\r\\n`\n"
        "It could get a simple result from http server fastly.",
    .global_init_cb                    = &nmapservice_global_init,
    .make_payload_cb                   = &nmapservice_make_payload,
    .get_payload_length_cb             = &nmapservice_get_payload_length,
    .validate_response_cb              = NULL,
    .handle_response_cb                = &nmapservice_handle_response,
    .close_cb                          = &nmapservice_close,
};
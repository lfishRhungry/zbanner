#ifndef NOT_FOUND_PCRE2

#include <string.h>

#include "probe-modules.h"
#include "../version.h"
#include "../util-out/logger.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../nmap/nmap-service.h"
#include "../target/target-set.h"

#define PROBER "NmapProbe"

/*for internal x-ref*/
extern Probe NmapProbe;

struct NmapTcpConf {
    struct NmapServiceProbeList *probe_list;
    struct NmapServiceProbe     *probe;
    char                        *probe_file;
    char                        *probe_name;
    char                        *softmatch;
};

static struct NmapTcpConf nmaptcp_conf = {0};

static ConfRes SET_softmatch(void *conf, const char *name, const char *value) {
    UNUSEDPARM(name);

    FREE(nmaptcp_conf.softmatch);

    nmaptcp_conf.softmatch = STRDUP(value);
    return Conf_OK;
}

static ConfRes SET_probe_name(void *conf, const char *name, const char *value) {
    UNUSEDPARM(name);

    FREE(nmaptcp_conf.probe_name);

    nmaptcp_conf.probe_name = STRDUP(value);
    return Conf_OK;
}

static ConfRes SET_probe_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(name);

    FREE(nmaptcp_conf.probe_file);

    nmaptcp_conf.probe_file = STRDUP(value);
    return Conf_OK;
}

static ConfParam nmapservice_parameters[] = {
    {"probe-file",
     SET_probe_file,
     Type_ARG,
     {"file", 0},
     "Specifies nmap-service-probes file for probes loading."},
    {"probe-name",
     SET_probe_name,
     Type_ARG,
     {"probe", 0},
     "Specifies a probe in nmap-service-probes file for sending."},
    {"softmatch",
     SET_softmatch,
     Type_ARG,
     {0},
     "Specifies what service has been softmatched for target ports before, "
     "so " PROBER " could use more accurate probes to reduce cost and just do "
     "hard matching.\n"
     "NOTE: This param exists because the strategy of Nmap services matching "
     "cannot be implemented completely in stateless mode."},

    {0}};

static bool nmap_init(const XConf *xconf) {
    if (!nmaptcp_conf.probe_file) {
        LOG(LEVEL_ERROR,
            "(" PROBER ") no nmap-service-probes file specified.\n");
        return false;
    }
    nmaptcp_conf.probe_list = nmapservice_read_file(nmaptcp_conf.probe_file);
    if (!nmaptcp_conf.probe_list) {
        LOG(LEVEL_ERROR, "(" PROBER ") invalid nmap-service-probes file: %s\n",
            nmaptcp_conf.probe_file);
        return false;
    }

    if (!nmaptcp_conf.probe_list->count) {
        LOG(LEVEL_ERROR, "(" PROBER ") no probe has been loaded from %s\n",
            nmaptcp_conf.probe_file);
        nmapservice_free(nmaptcp_conf.probe_list);
        return false;
    }

    if (!nmaptcp_conf.probe_name) {
        LOG(LEVEL_WARN,
            "(" PROBER ") No probe specified, use default `NULL`.\n");
        nmaptcp_conf.probe_name = STRDUP("NULL");
    }

    nmaptcp_conf.probe = nmapservice_get_probe_by_name(
        nmaptcp_conf.probe_list, nmaptcp_conf.probe_name, IP_PROTO_TCP);
    if (!nmaptcp_conf.probe) {
        LOG(LEVEL_ERROR, "(" PROBER ") invalid probe name: %s\n",
            nmaptcp_conf.probe_name);
        return false;
    }

    nmapservice_match_compile(nmaptcp_conf.probe_list);
    LOG(LEVEL_DEBUG, "(" PROBER ") probes loaded and compiled.\n");

    nmapservice_link_fallback(nmaptcp_conf.probe_list);
    LOG(LEVEL_DEBUG, "(" PROBER ") probe fallbacks linked.\n");

    return true;
}

static void nmap_close() {
    if (nmaptcp_conf.probe_list) {
        nmapservice_match_free(nmaptcp_conf.probe_list);
        LOG(LEVEL_DETAIL, "(" PROBER ") probes compilation freed.\n");

        nmapservice_free(nmaptcp_conf.probe_list);
        LOG(LEVEL_DETAIL, "(" PROBER ") probes freed.\n");

        nmaptcp_conf.probe_list = NULL;
    }

    nmaptcp_conf.probe = NULL;

    FREE(nmaptcp_conf.probe_file);
    FREE(nmaptcp_conf.probe_name);
    FREE(nmaptcp_conf.softmatch);
}

static size_t nmap_make_payload(ProbeTarget   *target,
                                unsigned char *payload_buf) {
    memcpy(payload_buf, nmaptcp_conf.probe->hellostring,
           nmaptcp_conf.probe->hellolength);

    return nmaptcp_conf.probe->hellolength;
}

static size_t nmap_get_payload_length(ProbeTarget *target) {

    return nmaptcp_conf.probe->hellolength;
}

unsigned nmap_handle_response(unsigned th_idx, ProbeTarget *target,
                              const unsigned char *px, unsigned sizeof_px,
                              OutItem *item) {
    struct NmapServiceProbeList *list  = nmaptcp_conf.probe_list;
    struct NmapServiceProbe     *probe = nmaptcp_conf.probe;

    struct ServiceProbeMatch *match = nmapservice_match_service(
        list, probe, px, sizeof_px, IP_PROTO_TCP, nmaptcp_conf.softmatch);

    if (match) {
        item->level = OUT_SUCCESS;

        safe_strcpy(item->classification, OUT_CLS_SIZE, "identified");
        safe_strcpy(item->reason, OUT_RSN_SIZE,
                    match->is_softmatch ? "softmatch" : "matched");

        dach_set_int(&item->report, "line", match->line);
        if (!match->is_softmatch && match->versioninfo) {
            dach_append(&item->report, "info", match->versioninfo->value,
                        strlen(match->versioninfo->value), LinkType_String);
        }
        dach_append(&item->report, "service", match->service,
                    strlen(match->service), LinkType_String);

        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "unknown");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

Probe NmapProbe = {
    .name       = "nmap",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 0,
    .params     = nmapservice_parameters,
    .short_desc = "Use specified Nmap probe to identify service over tcp.",
    .desc       = "NmapProbe sends specified Nmap probe from loaded "
                  "nmap-service-probes file and identifies service/version of "
                  "target tcp port. Unlike real Nmap, we just send one "
                  "specified probe and try to match the results. We can load "
                  "specific version of nmap-service-probes file by using "
                  "`--probe-file` subparam.\n"
                  "NOTE: This cannot perform a complete Nmap service "
                  "identification. Just for researching now.\n"
                  "Dependencies: PCRE2.",

    .init_cb               = &nmap_init,
    .make_payload_cb       = &nmap_make_payload,
    .get_payload_length_cb = &nmap_get_payload_length,
    .handle_response_cb    = &nmap_handle_response,
    .close_cb              = &nmap_close,
};

#endif /*ifndef NOT_FOUND_PCRE2*/
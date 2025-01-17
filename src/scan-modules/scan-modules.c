#include "scan-modules.h"

#include <string.h>
#include <stdio.h>

#include "../xconf.h"
#include "../util-out/xprint.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"

// clang-format off
extern Scanner TcpSynScan;
extern Scanner IcmpEchoScan;
extern Scanner IcmpTimeScan;
extern Scanner ArpReqScan;
extern Scanner NdpNsScan;
extern Scanner SctpInitScan;
extern Scanner ZBannerScan;
extern Scanner UdpScan;
extern Scanner TcpStateScan;
extern Scanner YarrpEchoScan;
extern Scanner YarrpUdpScan;
//! ADD YOUR SCAN MODULE HERE


Scanner *scan_modules_list[] = {
    &TcpSynScan, /*default scan module*/
    &IcmpEchoScan,
    &IcmpTimeScan,
    &ArpReqScan,
    &NdpNsScan,
    &SctpInitScan,
    &ZBannerScan,
    &UdpScan,
    &TcpStateScan,
    &YarrpEchoScan,
    &YarrpUdpScan,
    //! REGISTER YOUR SCAN MODULE HERE

    NULL /*keep the null tail*/
};
// clang-format on

Scanner *get_scan_module_by_name(const char *name) {
    int len = (int)(ARRAY_SIZE(scan_modules_list)) - 1;
    for (int i = 0; i < len; i++) {
        if (conf_equals(scan_modules_list[i]->name, name)) {
            return scan_modules_list[i];
        }
    }
    return NULL;
}

void list_searched_scan_modules(const char *name) {
    int len = (int)(ARRAY_SIZE(scan_modules_list)) - 1;
    int distance;
    for (int i = 0; i < len; i++) {
        distance = conf_fuzzy_distance(scan_modules_list[i]->name, name);
        if (distance < 0) {
            LOG(LEVEL_ERROR, "(%s) failed to matching.\n", __func__);
            break;
        }
        if (distance <= 2) {
            printf("    %s -> %s\n", scan_modules_list[i]->name,
                   scan_modules_list[i]->short_desc
                       ? scan_modules_list[i]->short_desc
                       : scan_modules_list[i]->desc);
        }
    }
}

void list_all_scan_modules() {
    int len = (int)(ARRAY_SIZE(scan_modules_list)) - 1;

    printf("\n");

    for (int i = 0; i < len; i++) {
        printf("  %d.%s\n", i + 1, scan_modules_list[i]->name);
        printf("    %s\n", scan_modules_list[i]->short_desc
                               ? scan_modules_list[i]->short_desc
                               : scan_modules_list[i]->desc);
        printf("\n");
    }
}

void help_scan_module(Scanner *module) {
    if (!module) {
        LOG(LEVEL_ERROR, "no specified scan module.\n");
        return;
    }

    printf("\n");
    printf("  Name of ScanModule:  %s\n", module->name);
    printf("  Probe Type Required: %s\n",
           get_probe_type_name(module->required_probe_type));
    printf("  Default BPF Filter:\n");
    xprint(module->bpf_filter ? module->bpf_filter : "null", 6, 80);
    printf("\n");
    printf("\n");
    printf("  Description:\n");
    xprint(module->desc, 6, 80);
    printf("\n");
    printf("\n");
    if (module->params) {
        for (unsigned j = 0; module->params[j].name; j++) {
            if (!module->params[j].help_text)
                continue;

            printf("  --%s", module->params[j].name);
            for (unsigned k = 0; module->params[j].alt_names[k]; k++) {
                printf(", %s", module->params[j].alt_names[k]);
            }
            printf("\n");
            xprint(module->params[j].help_text, 6, 80);
            printf("\n\n");
        }
    }

    printf("\n");
}

bool scan_init_nothing(const XConf *params) { return true; }

void scan_poll_nothing(unsigned th_idx) {}

void scan_close_nothing() { return; }

void scan_no_status(char *status) { status[0] = '\0'; }
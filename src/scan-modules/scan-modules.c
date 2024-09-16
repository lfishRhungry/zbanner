#include <string.h>
#include <stdio.h>

#include "scan-modules.h"
#include "../util-out/xprint.h"

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
//! REGIST YOUR SCAN MODULE HERE

static Scanner *scan_modules_list[] = {
    &TcpSynScan, /*default scan module*/
    &IcmpEchoScan,
    &IcmpTimeScan,
    &ArpReqScan,
    &NdpNsScan,
    &SctpInitScan,
    &ZBannerScan,
    &UdpScan,
    &TcpStateScan,
    //! REGIST YOUR SCAN MODULE HERE
};
// clang-format on

Scanner *get_scan_module_by_name(const char *name) {
    int len = (int)(ARRAY_SIZE(scan_modules_list));
    for (int i = 0; i < len; i++) {
        if (!strcmp(scan_modules_list[i]->name, name)) {
            return scan_modules_list[i];
        }
    }
    return NULL;
}

void list_all_scan_modules() {
    int len = (int)(ARRAY_SIZE(scan_modules_list));

    printf("\n");
    printf(XPRINT_STAR_LINE);
    printf("\n");
    printf("      Now contains [%d] ScanModules\n", len);
    printf(XPRINT_STAR_LINE);
    printf("\n");
    printf("\n");

    for (int i = 0; i < len; i++) {
        printf(XPRINT_DASH_LINE);
        printf("\n");
        printf("\n");
        printf("  Name of ScanModule:  %s\n", scan_modules_list[i]->name);
        printf("  Description:\n");
        xprint(scan_modules_list[i]->short_desc
                   ? scan_modules_list[i]->short_desc
                   : scan_modules_list[i]->desc,
               6, 80);
        printf("\n");
        printf("\n");
    }
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
}

void help_scan_module(Scanner *module) {
    if (!module) {
        LOG(LEVEL_ERROR, "No specified scan module.\n");
        return;
    }

    printf("\n");
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
    printf("  Name of ScanModule:  %s\n", module->name);
    printf("  Probe Type Required: %s\n",
           get_probe_type_name(module->required_probe_type));
    printf("  Supports Timeout:    %s\n",
           module->support_timeout ? "Yes\n" : "No\n");
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
                printf(", --%s", module->params[j].alt_names[k]);
            }
            printf("\n");
            xprint(module->params[j].help_text, 6, 80);
            printf("\n\n");
        }
    }

    printf("\n");
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
}

bool scan_init_nothing(const XConf *params) { return true; }

void scan_poll_nothing(unsigned th_idx) {}

void scan_close_nothing() { return; }

void scan_no_timeout(uint64_t entropy, ScanTmEvent *event, OutItem *item,
                     STACK *stack, FHandler *handler) {
    item->no_output = 1;
}

void scan_no_status(char *status) { status[0] = '\0'; }
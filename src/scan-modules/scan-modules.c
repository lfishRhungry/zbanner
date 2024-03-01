#include <string.h>
#include <stdio.h>

#include "scan-modules.h"
#include "../util/xprint.h"

extern struct ScanModule TcpSynScan;
extern struct ScanModule IcmpEchoScan;
extern struct ScanModule IcmpTimeScan;
extern struct ScanModule ArpReqScan;
extern struct ScanModule SctpInitScan;
extern struct ScanModule ZBannerScan;
extern struct ScanModule UdpProbeScan;
//! REGIST YOUR SCAN MODULE HERE

static struct ScanModule *scan_modules_list[] = {
    &TcpSynScan, /*default scan module*/
    &IcmpEchoScan,
    &IcmpTimeScan,
    &ArpReqScan,
    &SctpInitScan,
    &ZBannerScan,
    &UdpProbeScan,
    //! REGIST YOUR SCAN MODULE HERE
};

struct ScanModule *get_scan_module_by_name(const char *name)
{
    int len = (int)(sizeof(scan_modules_list)/sizeof(struct ScanModule *));
    for (int i = 0; i < len; i++) {
        if (!strcmp(scan_modules_list[i]->name, name)) {
            return scan_modules_list[i];
        }
    }
    return NULL;
}

void list_all_scan_modules()
{
    int len = (int)(sizeof(scan_modules_list)/sizeof(struct ScanModule *));
    
    printf("\n");
    printf("\n");
    printf("      Now contains [%d] ScanModules\n", len);
    printf("\n");
    printf("\n");

    for (int i = 0; i < len; i++) {
        printf(XPRINT_DASH_LINE);
        printf("\n");
        printf("\n");
        printf("  ScanModule Name: %s\n", scan_modules_list[i]->name);
        printf("\n");
        printf("  Required Probe Type: %s\n", get_probe_type_name(scan_modules_list[i]->required_probe_type));
        printf("\n");
        printf("  BPF Filter:\n");
        print_with_indent(scan_modules_list[i]->bpf_filter?scan_modules_list[i]->bpf_filter:"null", 6, 80);
        printf("\n");
        printf("\n");
        printf("  Description:\n");
        print_with_indent(scan_modules_list[i]->desc, 6, 80);
        printf("\n");
    }
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
}

int scan_init_nothing(const void *params)
{
    return 1;
}

int scan_filter_nothing(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned is_myip, unsigned is_myport)
{
    return 1;
}

int scan_valid_all(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px)
{
    return 1;
}

int scan_no_dedup(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    ipaddress *ip_them, unsigned *port_them,
    ipaddress *ip_me, unsigned *port_me, unsigned *type)
{
    return 0;
}

int scan_response_nothing(
    struct PreprocessedInfo *parsed, uint64_t entropy,
    const unsigned char *px, unsigned sizeof_px,
    unsigned char *r_px, unsigned sizeof_r_px,
    size_t *r_length, unsigned index)
{
    *r_length=0;
    return 0;
}

void scan_close_nothing()
{
    return;
}
#include <string.h>
#include <stdio.h>

#include "scan-modules.h"

extern struct ScanModule TcpSynScan;
extern struct ScanModule IcmpEchoScan;
extern struct ScanModule ArpReqScan;
extern struct ScanModule SctpInitScan;
extern struct ScanModule ZBannerScan;
extern struct ScanModule UdpProbeScan;
//! REGIST YOUR SCAN MODULE HERE

static struct ScanModule *scan_modules_list[] = {
    &TcpSynScan, /*default scan module*/
    &IcmpEchoScan,
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
    printf("\nNow contains %d ScanModules:\n\n", len);

    for (int i = 0; i < len; i++) {
        printf("========================\n\n");
        printf("ScanModule Name: %s\n", scan_modules_list[i]->name);
        printf("Required Probe Type: %s\n", get_probe_type_name(scan_modules_list[i]->required_probe_type));
        printf("Description:\n%s\n", scan_modules_list[i]->desc);
    }
    printf("========================\n");
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
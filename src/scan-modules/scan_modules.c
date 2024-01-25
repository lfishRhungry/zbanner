#include <string.h>
#include <stdio.h>

#include "scan_modules.h"

extern struct ScanModule TcpSynScan;
extern struct ScanModule IcmpEchoScan;
//! REGIST YOUR SCAN MODULE HERE

static struct ScanModule *scan_modules_list[] = {
    &TcpSynScan, /*default scan module*/
    &IcmpEchoScan,
    //! REGIST YOUR SCAN MODULE HERE
};

struct ScanModule *get_scan_module_by_name(const char *name)
{
    int len = (int)(sizeof(struct ScanModule)/sizeof(struct StatelessProbe *));
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
        printf("ScanModule Name: %s\n\n", scan_modules_list[i]->name);
        printf("Description:\n%s\n", scan_modules_list[i]->description);
    }
    printf("========================\n");
}
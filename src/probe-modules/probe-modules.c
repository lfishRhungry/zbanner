#include <string.h>
#include <stdio.h>

#include "probe-modules.h"
#include "../util/mas-safefunc.h"

/*
This is an Application Probe(or Request) Plugin System
*/



extern struct ProbeModule NullProbe;
extern struct ProbeModule GetRequestProbe;
extern struct ProbeModule LzrProbe;
extern struct ProbeModule LzrWaitProbe;
extern struct ProbeModule LzrHttpProbe;
extern struct ProbeModule LzrFtpProbe;
//! ADD YOUR PROBE HERE



static struct ProbeModule *probe_modules_list[] = {
    &NullProbe, /* its also the default probe*/
    &GetRequestProbe,
    &LzrProbe,
    &LzrWaitProbe,
    &LzrHttpProbe,
    &LzrFtpProbe,
    //! ADD YOUR PROBE HERE
};


struct ProbeModule *get_probe_module_by_name(const char *name)
{
    int len = (int)(sizeof(probe_modules_list)/sizeof(struct ProbeModule *));
    for (int i = 0; i < len; i++) {
        if (!strcmp(probe_modules_list[i]->name, name)) {
            return probe_modules_list[i];
        }
    }
    return NULL;
}

static char *get_type_name_by_flag(unsigned flag)
{
    if (flag==1)
        return " tcp";
    else if (flag>>1==1)
        return " udp";
    else if (flag>>2==1)
        return " sctp";
    return "";
}

void list_all_probe_modules()
{
    int len = (int)(sizeof(probe_modules_list)/sizeof(struct ProbeModule *));
    printf("\nNow contains %d ProbeModules:\n\n", len);

    for (int i = 0; i < len; i++) {
        printf("========================\n\n");
        printf("ProbeModule Name: %s\n", probe_modules_list[i]->name);
        printf("ProbeModule Type:");
        for (unsigned i=1;i<ProbeType_MAX;i<<=1) {
            if ((probe_modules_list[i]->type & i) > 0)
                puts(get_type_name_by_flag(i));
        }
        printf("\n");
        printf("Description:\n%s\n", probe_modules_list[i]->desc);
    }
    printf("========================\n");
}


void
just_report_banner(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    const unsigned char *px, unsigned sizeof_px,
    char *report, unsigned rpt_length)
{
    normalize_string(px, sizeof_px, report, rpt_length);
}
#include <string.h>
#include <stdio.h>

#include "probe-modules.h"

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

static char *get_probe_type_name(enum ProbeModuleType type)
{
    switch (type) {
        case Raw_Probe:
            return "raw";
        case Tcp_Probe:
            return "tcp";
        case Udp_Probe:
            return "udp";
        default:
            break;
    }
    return "unknown";
}

void list_all_probe_modules()
{
    int len = (int)(sizeof(probe_modules_list)/sizeof(struct ProbeModule *));
    printf("\nNow contains %d stateless probes:\n\n", len);

    for (int i = 0; i < len; i++) {
        printf("========================\n\n");
        printf("Probe Name: %s\n", probe_modules_list[i]->name);
        printf("Probe Type: %s\n", get_probe_type_name(probe_modules_list[i]->type));
        printf("Probe Help:\n%s\n", probe_modules_list[i]->help_text);
    }
    printf("========================\n");
}

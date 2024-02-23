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
extern struct ProbeModule EchoProbe;
//! ADD YOUR PROBE HERE



static struct ProbeModule *probe_modules_list[] = {
    &NullProbe, /* its also the default probe*/
    &GetRequestProbe,
    &LzrProbe,
    &LzrWaitProbe,
    &LzrHttpProbe,
    &LzrFtpProbe,
    &EchoProbe,
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

const char *
get_probe_type_name(const enum ProbeType type)
{
    switch (type) {
        case ProbeType_NULL:
            return "null";
        case ProbeType_TCP:
            return "tcp";
        case ProbeType_UDP:
            return "udp";
        default:
            return "";
    }
}

void list_all_probe_modules()
{
    int len = (int)(sizeof(probe_modules_list)/sizeof(struct ProbeModule *));
    printf("\nNow contains %d ProbeModules:\n\n", len);

    for (int i = 0; i < len; i++) {
        printf("========================\n\n");
        printf("ProbeModule Name: %s\n", probe_modules_list[i]->name);
        printf("ProbeModule Type: %s\n", get_probe_type_name(probe_modules_list[i]->type));
        printf("Description:\n%s\n", probe_modules_list[i]->desc);
    }
    printf("========================\n");
}

int probe_init_nothing(const void *params)
{
    return 1;
}

size_t
probe_make_no_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    return 0;
}

size_t
probe_no_payload_length(struct ProbeTarget *target)
{
    return 0;
}

void
probe_report_nothing(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    char *report, unsigned rpt_length)
{
    return;
}

void
probe_just_report_banner(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    char *report, unsigned rpt_length)
{
    normalize_string(px, sizeof_px, report, rpt_length);
}

void probe_close_nothing()
{
    return;
}
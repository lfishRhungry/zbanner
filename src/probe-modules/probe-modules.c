#include <string.h>
#include <stdio.h>

#include "probe-modules.h"
#include "../util-data/safe-string.h"
#include "../util-out/xprint.h"

/*
This is an Application-layer Probe(or Request) Plugin System
*/



//! ADD YOUR PROBE HERE
extern struct ProbeModule NullProbe;
extern struct ProbeModule HttpProbe;
extern struct ProbeModule HttpStateProbe;
extern struct ProbeModule EchoProbe;
extern struct ProbeModule GetStateProbe;
extern struct ProbeModule JarmProbe;
extern struct ProbeModule TlsStateProbe;
extern struct ProbeModule NmapTcpProbe;
extern struct ProbeModule DnsProbe;
extern struct ProbeModule LuaTcpProbe;
extern struct ProbeModule LuaUdpProbe;
extern struct ProbeModule SnmpProbe;
extern struct ProbeModule HelloProbe;
extern struct ProbeModule HelloUdpProbe;
extern struct ProbeModule HelloStateProbe;
extern struct ProbeModule RecogProbe;
extern struct ProbeModule RecogUdpProbe;
extern struct ProbeModule RecogStateProbe;
extern struct ProbeModule CloseStateProbe;
/*for lzr probes*/
extern struct ProbeModule LzrProbe;
extern struct ProbeModule LzrHttpProbe;
extern struct ProbeModule LzrTlsProbe;
extern struct ProbeModule LzrFtpProbe;
extern struct ProbeModule LzrPop3Probe;
extern struct ProbeModule LzrImapProbe;
extern struct ProbeModule LzrSmtpProbe;
extern struct ProbeModule LzrSshProbe;
extern struct ProbeModule LzrSocks5Probe;
extern struct ProbeModule LzrTelnetProbe;
extern struct ProbeModule LzrFixProbe;
extern struct ProbeModule LzrSmbProbe;
extern struct ProbeModule LzrMqttProbe;
extern struct ProbeModule LzrAmqpProbe;
extern struct ProbeModule LzrMysqlProbe;
extern struct ProbeModule LzrMongodbProbe;
extern struct ProbeModule LzrRedisProbe;
extern struct ProbeModule LzrPostgresProbe;
extern struct ProbeModule LzrMssqlProbe;
extern struct ProbeModule LzrOracleProbe;
extern struct ProbeModule LzrRdpProbe;
extern struct ProbeModule LzrX11Probe;
extern struct ProbeModule LzrVncProbe;
extern struct ProbeModule LzrK8sProbe;
extern struct ProbeModule LzrRtspProbe;
extern struct ProbeModule LzrModbusProbe;
extern struct ProbeModule LzrSiemensProbe;
extern struct ProbeModule LzrBgpProbe;
extern struct ProbeModule LzrPptpProbe;
extern struct ProbeModule LzrDnsProbe;
extern struct ProbeModule LzrIpmiProbe;
extern struct ProbeModule LzrDnp3Probe;
extern struct ProbeModule LzrFoxProbe;
extern struct ProbeModule LzrMemcachedAsciiProbe;
extern struct ProbeModule LzrMemcachedBinaryProbe;
extern struct ProbeModule LzrIppProbe;
extern struct ProbeModule LzrWaitProbe;
extern struct ProbeModule LzrNewlinesProbe;
extern struct ProbeModule LzrNewlines50Probe;



//! ADD YOUR PROBE HERE
static struct ProbeModule *probe_modules_list[] = {
    &NullProbe, /* its also the default probe*/
    &HttpProbe,
    &HttpStateProbe,
    &EchoProbe,
    &GetStateProbe,

#ifndef NOT_FOUND_OPENSSL
    &JarmProbe,
    &TlsStateProbe,
#endif

#ifndef NOT_FOUND_PCRE2
    &NmapTcpProbe,
#endif

    &DnsProbe,
    &LuaTcpProbe,
    &LuaUdpProbe,
    &SnmpProbe,
    &HelloProbe,

#ifndef NOT_FOUND_PCRE2
    &HelloUdpProbe,
#endif

    &HelloStateProbe,

#ifndef NOT_FOUND_PCRE2
    &RecogProbe,
    &RecogUdpProbe,
    &RecogStateProbe,
#endif

    &CloseStateProbe,

    /*for lzr probes*/
    &LzrProbe,
    &LzrHttpProbe,
    &LzrTlsProbe,
    &LzrFtpProbe,
    &LzrPop3Probe,
    &LzrImapProbe,
    &LzrSmtpProbe,
    &LzrSshProbe,
    &LzrSocks5Probe,
    &LzrTelnetProbe,
    &LzrFixProbe,
    &LzrSmbProbe,
    &LzrMqttProbe,
    &LzrAmqpProbe,
    &LzrMysqlProbe,
    &LzrMongodbProbe,
    &LzrRedisProbe,
    &LzrPostgresProbe,
    &LzrMssqlProbe,
    &LzrOracleProbe,
    &LzrRdpProbe,
    &LzrX11Probe,
    &LzrVncProbe,
    &LzrK8sProbe,
    &LzrRtspProbe,
    &LzrModbusProbe,
    &LzrSiemensProbe,
    &LzrBgpProbe,
    &LzrPptpProbe,
    &LzrDnsProbe,
    &LzrIpmiProbe,
    &LzrDnp3Probe,
    &LzrFoxProbe,
    &LzrMemcachedAsciiProbe,
    &LzrMemcachedBinaryProbe,
    &LzrIppProbe,
    &LzrWaitProbe,
    &LzrNewlinesProbe,
    &LzrNewlines50Probe,
};


struct ProbeModule *get_probe_module_by_name(const char *name)
{
    int len = (int)ARRAY_SIZE(probe_modules_list);
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
        case ProbeType_STATE:
            return "state";
        default:
            return "";
    }
}

static const char *
get_multi_mode_name(const enum MultiMode type)
{
    switch (type) {
        case Multi_Null:
            return "no multi-probe";
        case Multi_Direct:
            return "send directly";
        case Multi_IfOpen:
            return "send if port open";
        case Multi_AfterHandle:
            return "send after handled";
        case Multi_DynamicNext:
            return "send next dynamicly";
        default:
            return "";
    }
}

int probe_type_to_string(unsigned type, char *string, size_t str_len)
{
    int ret = 0;

    ret = snprintf(string, str_len, "%s%s%s",
            (type&ProbeType_TCP)?"tcp|":"",
            (type&ProbeType_UDP)?"udp|":"",
            (type&ProbeType_STATE)?"state|":""
            );
    if (string[0] == '\0') {
        ret = snprintf(string, str_len, "no probe");
    }
    else {
        string[strlen(string)-1] = '\0';
        ret--;
    }

    return ret;
}

void list_all_probe_modules()
{
    int len = (int)ARRAY_SIZE(probe_modules_list);

    printf("\n");
    printf(XPRINT_STAR_LINE);
    printf("\n");
    printf("      Now contains [%d] ProbeModules\n", len);
    printf(XPRINT_STAR_LINE);
    printf("\n");
    printf("\n");

    for (int i = 0; i < len; i++) {
        printf(XPRINT_DASH_LINE);
        printf("\n");
        printf("\n");
        printf("  ProbeModule Name: %s\n", probe_modules_list[i]->name);
        printf("  Description:\n");
        xprint(probe_modules_list[i]->desc, 6, 80);
        printf("\n");
        printf("\n");
    }
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
}

void help_probe_module(struct ProbeModule *module)
{
    if (!module) {
        LOG(LEVEL_ERROR, "No specified probe module.\n");
        return;
    }

    printf("\n");
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
    printf("  ProbeModule Name: %s\n", module->name);
    printf("  ProbeModule Type: %s\n", get_probe_type_name(module->type));
    printf("  Multi-probe mode: %s\n", get_multi_mode_name(module->multi_mode));
    printf("  Multi-probe count: %u\n", module->multi_num);
    printf("  Hello wait second: %u (for stateful probe)\n", module->hello_wait);
    printf("\n");
    printf("  Description:\n");
    xprint(module->desc, 6, 80);
    printf("\n");
    printf("\n");
    if (module->params) {
        for (unsigned j=0; module->params[j].name; j++) {

            if (!module->params[j].help_text)
                continue;

            printf("  --%s", module->params[j].name);
            for (unsigned k=0; module->params[j].alt_names[k]; k++) {
                printf(", --%s", module->params[j].alt_names[k]);
            }
            printf("\n");
            xprint(module->params[j].help_text, 6, 80);
            printf("\n\n");
        }
    }
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
}

bool probe_init_nothing(const struct Xconf *xconf)
{
    return true;
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

unsigned
probe_report_nothing(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    OutItem *item)
{
    item->no_output = 1;
    return 0;
}

unsigned
probe_just_report_banner(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    OutItem *item)
{
    item->level = OUT_SUCCESS;
    dach_append_normalized(&item->report, "banner", px, sizeof_px);

    return 0;
}

void probe_close_nothing()
{
    return;
}

bool probe_conn_init_nothing(struct ProbeState *state, struct ProbeTarget *target)
{
    return true;
}

void probe_conn_close_nothing(struct ProbeState *state, struct ProbeTarget *target)
{
    return;
}

unsigned
probe_no_timeout(struct ProbeTarget *target, OutItem *item)
{
    item->no_output = 1;
    return 0;
}


bool probe_all_valid(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px)
{
    return true;
}
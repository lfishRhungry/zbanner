#include <string.h>
#include <stdio.h>

#include "probe-modules.h"
#include "../util-data/safe-string.h"
#include "../util-out/xprint.h"

/*
This is an Application Probe(or Request) Plugin System
*/



//! ADD YOUR PROBE HERE
extern struct ProbeModule NullProbe;
extern struct ProbeModule HttpProbe;
extern struct ProbeModule EchoProbe;
extern struct ProbeModule JarmProbe;
extern struct ProbeModule GetStateProbe;
extern struct ProbeModule TlsStateProbe;
extern struct ProbeModule NmapTcpProbe;
extern struct ProbeModule DnsProbe;
/*for lzr probes*/
extern struct ProbeModule LzrProbe;
extern struct ProbeModule LzrHttpProbe;
extern struct ProbeModule LzrTlsProbe;
extern struct ProbeModule LzrFtpProbe;
extern struct ProbeModule LzrPop3Probe;
extern struct ProbeModule LzrImapProbe;
extern struct ProbeModule LzrSmtpProbe;
extern struct ProbeModule LzrSshProbe;
extern struct ProbeModule LzrTelnetProbe;
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
    &EchoProbe,
    &JarmProbe,
    &GetStateProbe,
    &TlsStateProbe,
    &NmapTcpProbe,
    &DnsProbe,
    /*for lzr probes*/
    &LzrProbe,
    &LzrHttpProbe,
    &LzrTlsProbe,
    &LzrFtpProbe,
    &LzrPop3Probe,
    &LzrImapProbe,
    &LzrSmtpProbe,
    &LzrSshProbe,
    &LzrTelnetProbe,
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
        printf("\n");
        printf("  ProbeModule Type: %s\n", get_probe_type_name(probe_modules_list[i]->type));
        printf("\n");
        printf("  Description:\n");
        xprint(probe_modules_list[i]->desc, 6, 80);
        printf("\n");
        printf("\n");
        if (probe_modules_list[i]->params) {
            for (unsigned j=0; probe_modules_list[i]->params[j].name; j++) {

                if (!probe_modules_list[i]->params[j].helps)
                    continue;

                printf("  --%s", probe_modules_list[i]->params[j].name);
                for (unsigned k=0; probe_modules_list[i]->params[j].alts[k]; k++) {
                    printf(", --%s", probe_modules_list[i]->params[j].alts[k]);
                }
                printf("\n");
                xprint(probe_modules_list[i]->params[j].helps, 6, 80);
                printf("\n\n");
            }
        }
        printf("\n");
    }
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
}

bool probe_global_init_nothing(const struct Xconf *xconf)
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
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px > 0) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "serving");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "banner exists");
    } else {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "no serving");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "timeout");
    }

    return 0;
}

unsigned
probe_just_report_banner(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px > 0) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "serving");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "banner exists");
        normalize_string(px, sizeof_px, item->report, OUTPUT_RPT_LEN);
    } else {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "no serving");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "timeout");
    }

    return 0;
}

void probe_close_nothing()
{
    return;
}

void probe_conn_init_nothing(struct ProbeState *state, struct ProbeTarget *target)
{
    return;
}

void probe_conn_close_nothing(struct ProbeState *state, struct ProbeTarget *target)
{
    return;
}
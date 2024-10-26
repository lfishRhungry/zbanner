#include <string.h>
#include <stdio.h>

#include "probe-modules.h"
#include "../util-data/safe-string.h"
#include "../util-out/xprint.h"

/*
This is an Application-layer Probe(or Request) Plugin System
*/

// clang-format off
//! ADD YOUR PROBE HERE
extern Probe NullProbe;
extern Probe HttpProbe;
extern Probe HttpStateProbe;
extern Probe EchoProbe;
extern Probe GetStateProbe;
extern Probe JarmProbe;
extern Probe TlsStateProbe;
extern Probe DnsProbe;
extern Probe LuaTcpProbe;
extern Probe LuaUdpProbe;
extern Probe SnmpProbe;
extern Probe HelloProbe;
extern Probe HelloUdpProbe;
extern Probe HelloStateProbe;
extern Probe RecogProbe;
extern Probe RecogUdpProbe;
extern Probe RecogStateProbe;
extern Probe CloseStateProbe;
extern Probe TlsHelloProbe;
/*for lzr probes*/
extern Probe LzrProbe;
extern Probe LzrHttpProbe;
extern Probe LzrTlsProbe;
extern Probe LzrFtpProbe;
extern Probe LzrPop3Probe;
extern Probe LzrImapProbe;
extern Probe LzrSmtpProbe;
extern Probe LzrSshProbe;
extern Probe LzrSocks5Probe;
extern Probe LzrTelnetProbe;
extern Probe LzrFixProbe;
extern Probe LzrSmbProbe;
extern Probe LzrMqttProbe;
extern Probe LzrAmqpProbe;
extern Probe LzrMysqlProbe;
extern Probe LzrMongodbProbe;
extern Probe LzrRedisProbe;
extern Probe LzrPostgresProbe;
extern Probe LzrMssqlProbe;
extern Probe LzrOracleProbe;
extern Probe LzrRdpProbe;
extern Probe LzrX11Probe;
extern Probe LzrVncProbe;
extern Probe LzrK8sProbe;
extern Probe LzrRtspProbe;
extern Probe LzrModbusProbe;
extern Probe LzrSiemensProbe;
extern Probe LzrBgpProbe;
extern Probe LzrPptpProbe;
extern Probe LzrDnsProbe;
extern Probe LzrIpmiProbe;
extern Probe LzrDnp3Probe;
extern Probe LzrFoxProbe;
extern Probe LzrMemcachedAsciiProbe;
extern Probe LzrMemcachedBinaryProbe;
extern Probe LzrIppProbe;
extern Probe LzrWaitProbe;
extern Probe LzrNewlinesProbe;
extern Probe LzrNewlines50Probe;

//! ADD YOUR PROBE HERE
static Probe *probe_modules_list[] = {
    &NullProbe, /* its also the default probe*/
    &HttpProbe,
    &HttpStateProbe,
    &EchoProbe,
    &GetStateProbe,

#ifndef NOT_FOUND_OPENSSL
    &JarmProbe,
    &TlsStateProbe,
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
    &TlsHelloProbe,

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
// clang-format on

Probe *get_probe_module_by_name(const char *name) {
    int len = (int)ARRAY_SIZE(probe_modules_list);
    for (int i = 0; i < len; i++) {
        if (!strcmp(probe_modules_list[i]->name, name)) {
            return probe_modules_list[i];
        }
    }
    return NULL;
}

const char *get_probe_type_name(const ProbeType type) {
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

static const char *get_multi_mode_name(const MultiMode type) {
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

int probe_type_to_string(unsigned type, char *string, size_t str_len) {
    int ret = 0;

    ret = snprintf(string, str_len, "%s%s%s",
                   (type & ProbeType_TCP) ? "tcp|" : "",
                   (type & ProbeType_UDP) ? "udp|" : "",
                   (type & ProbeType_STATE) ? "state|" : "");
    if (string[0] == '\0') {
        ret = snprintf(string, str_len, "no probe");
    } else {
        string[strlen(string) - 1] = '\0';
        ret--;
    }

    return ret;
}

void list_all_probe_modules() {
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
        xprint(probe_modules_list[i]->short_desc
                   ? probe_modules_list[i]->short_desc
                   : probe_modules_list[i]->desc,
               6, 80);
        printf("\n");
        printf("\n");
    }
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
}

void help_probe_module(Probe *module) {
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
    printf("  Hello wait second: %u (for stateful probe)\n",
           module->hello_wait);
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
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
}

bool probe_init_nothing(const XConf *xconf) { return true; }

size_t probe_make_no_payload(ProbeTarget *target, unsigned char *payload_buf) {
    return 0;
}

size_t probe_no_payload_length(ProbeTarget *target) { return 0; }

unsigned probe_report_nothing(unsigned th_idx, ProbeTarget *target,
                              const unsigned char *px, unsigned sizeof_px,
                              OutItem *item) {
    item->no_output = 1;
    return 0;
}

unsigned probe_just_report_banner(unsigned th_idx, ProbeTarget *target,
                                  const unsigned char *px, unsigned sizeof_px,
                                  OutItem *item) {
    item->level = OUT_SUCCESS;
    dach_append_normalized(&item->report, "banner", px, sizeof_px,
                           LinkType_String);

    return 0;
}

void probe_close_nothing() { return; }

bool probe_conn_init_nothing(ProbeState *state, ProbeTarget *target) {
    return true;
}

void probe_conn_close_nothing(ProbeState *state, ProbeTarget *target) {
    return;
}

bool probe_all_response_valid(ProbeTarget *target, const unsigned char *px,
                              unsigned sizeof_px) {
    return true;
}
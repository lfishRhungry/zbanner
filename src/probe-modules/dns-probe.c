#include "probe-modules.h"
#include "../proto/proto-dns.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/data-convert.h"

/*for internal x-ref*/
extern struct ProbeModule DnsProbe;

struct DnsConf {
    char *req_name;
    dns_record_type req_type;
};

static struct DnsConf dns_conf = {0};

static enum Config_Res SET_req_name(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    char  *str     = STRDUP(value);
    size_t str_len = strlen(str);
    if (str_len == 0) {
        LOG(LEVEL_ERROR, "[-] request name of dns is error.\n");
        return CONF_ERR;
    }

    dns_conf.req_name = str;

    return CONF_OK;
}

static enum Config_Res SET_req_type(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    size_t str_len = strlen(value);
    if (str_len == 0) {
        LOG(LEVEL_ERROR, "[-] request type of dns is error.\n");
        return CONF_ERR;
    }

    dns_conf.req_type = dns_str_to_record_type(value);

    if (dns_conf.req_type==DNS_REC_INVALID) {
        LOG(LEVEL_ERROR, "[-] invalide request type of dns.\n");
        return CONF_ERR;
    }

    return CONF_OK;
}

static struct ConfigParam dns_parameters[] = {
    {
        "req-name",
        SET_req_name,
        F_NONE,
        {"name", 0},
        "Specifies dns request name like 'www.google.com'."
    },
    {
        "req-type",
        SET_req_type,
        F_NONE,
        {"type", 0},
        "Specifies dns request type like 'A', 'AAAA'."
    },

    {0}
};

static bool
dns_global_init(const struct Xconf *xconf)
{
    if (!dns_conf.req_name) {
        LOG(LEVEL_ERROR, "[-] Please specify a dns request name by --req-name.\n");
        return false;
    }

    if (dns_conf.req_type == 0) {
        LOG(LEVEL_HINT, "[-] Use default dns A record type because no request type was specified by --req-type.\n");
        dns_conf.req_type = DNS_REC_A;
    }

    return true;
}

static size_t
dns_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    int res_len = dns_question_create(payload_buf,
        dns_conf.req_name, dns_conf.req_type, target->cookie & 0xFFFF);

    return (size_t)res_len;
}

static bool
dns_validate_response(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px)
{
    if (sizeof_px<2) {
        return false;
    }

    /*maybe we can do more validation to ensure this is a valid dns packet*/
    if (U16_EQUAL_TO_BE(px, target->cookie & 0xFFFF)) {
        return true;
    }

    return false;
}

static unsigned
dns_handle_response(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "unknown");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "no response");
        return 0;
    }

    dns_pkt_t dns_pkt;
    
    if (!dns_parse_reply((uint8_t *)px, sizeof_px, &dns_pkt)) {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "invalid");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not dns");
        return 0;
    }

    item->level = Output_SUCCESS;
    safe_strcpy(item->classification, OUTPUT_CLS_LEN, "dns reply");
    safe_strcpy(item->reason, OUTPUT_RSN_LEN, "valid dns");

    if (dns_pkt.head.header.ans_count > 0) {
        dns_record_t rec = dns_pkt.body.ans[0];
        int offset = 0;
        offset += snprintf(item->report+offset, OUTPUT_RPT_LEN-offset,
            dns_record_type2str(rec.type));
        offset += snprintf(item->report+offset, OUTPUT_RPT_LEN-offset,
            " ");
        offset += snprintf(item->report+offset, OUTPUT_RPT_LEN-offset,
            dns_raw_record_data2str(&rec, (uint8_t *)px, (uint8_t *)px+sizeof_px, true));
    }

    return 0;
}

static void dns_close()
{
    if (dns_conf.req_name) {
        free(dns_conf.req_name);
        dns_conf.req_name = NULL;
    }
}

struct ProbeModule DnsProbe = {
    .name       = "dns",
    .type       = ProbeType_UDP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = dns_parameters,
    .desc =
        "DnsProbe sends a dns request specified by user to target udp port and "
        "expects a dns reply.",
    .global_init_cb                 = &dns_global_init,
    .make_payload_cb                = &dns_make_payload,
    .get_payload_length_cb          = NULL,
    .validate_response_cb           = &dns_validate_response,
    .handle_response_cb             = &dns_handle_response,
    .close_cb                       = &dns_close,
};
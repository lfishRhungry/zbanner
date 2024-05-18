#include <stdlib.h>

#include "scan-modules.h"
#include "../massip/massip-cookie.h"
#include "../templ/templ-sctp.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"

extern struct ScanModule SctpInitScan; /*for internal x-ref*/

struct SctpInitConf {
    unsigned record_ttl:1;
    unsigned record_ipid:1;
};

static struct SctpInitConf sctpinit_conf = {0};

static enum Config_Res SET_record_ttl(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    sctpinit_conf.record_ttl = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_record_ipid(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    sctpinit_conf.record_ipid = parseBoolean(value);

    return CONF_OK;
}

static struct ConfigParam sctpinit_parameters[] = {
    {
        "record-ttl",
        SET_record_ttl,
        F_BOOL,
        {"ttl", 0},
        "Records TTL for IPv4 or Hop Limit for IPv6 in SCTP response."
    },
    {
        "record-ipid",
        SET_record_ipid,
        F_BOOL,
        {"ipid", 0},
        "Records IPID of SCTP response just for IPv4."
    },

    {0}
};
static bool
sctpinit_transmit(
    uint64_t entropy,
    struct ScanTarget *target,
    struct ScanTmEvent *event,
    unsigned char *px, size_t *len)
{
    /*we just handle tcp target*/
    if (target->proto != Port_SCTP)
        return false;

    unsigned cookie = get_cookie(target->ip_them, target->port_them,
        target->ip_me, target->port_me, entropy);

    *len = sctp_create_packet(target->ip_them, target->port_them,
        target->ip_me, target->port_me,
        cookie, px, PKT_BUF_LEN);
    
    /*add timeout*/
    event->need_timeout = 1;

    return false;
}

static void
sctpinit_validate(
    uint64_t entropy,
    struct Received *recved,
    struct PreHandle *pre)
{
    /*record all sctp to me*/
    if (recved->parsed.found == FOUND_SCTP
        && recved->is_myip
        && recved->is_myport)
        pre->go_record = 1;
    else return;

    /*packet is too short*/
    if (recved->parsed.transport_offset + 16 > recved->length)
        return;

    ipaddress ip_them  = recved->parsed.src_ip;
    ipaddress ip_me    = recved->parsed.dst_ip;
    unsigned port_them = recved->parsed.port_src;
    unsigned port_me   = recved->parsed.port_dst;

    unsigned veri_tag  = SCTP_VERI_TAG(recved->packet, recved->parsed.transport_offset);
    unsigned cookie    = get_cookie(ip_them, port_them, ip_me, port_me, entropy);

    if (cookie != veri_tag)
        return;

    if (SCTP_IS_CHUNK_TYPE(recved->packet, recved->parsed.transport_offset,
        SCTP_CHUNK_TYPE_INIT_ACK)) {
        pre->go_dedup = 1;
    } else if (SCTP_IS_CHUNK_TYPE(recved->packet, recved->parsed.transport_offset,
        SCTP_CHUNK_TYPE_ABORT)) {
        pre->go_dedup = 1;
    }
}

static void
sctpinit_handle(
    unsigned th_idx,
    uint64_t entropy,
    struct Received *recved,
    struct OutputItem *item,
    struct stack_t *stack,
    struct FHandler *handler)
{
    if (SCTP_IS_CHUNK_TYPE(recved->packet, recved->parsed.transport_offset,
        SCTP_CHUNK_TYPE_INIT_ACK)) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->reason, OUT_RSN_SIZE, "init-ack");
        safe_strcpy(item->classification, OUT_CLS_SIZE, "open");
    } else if (SCTP_IS_CHUNK_TYPE(recved->packet, recved->parsed.transport_offset,
        SCTP_CHUNK_TYPE_ABORT)) {
        item->level = Output_FAILURE;
        safe_strcpy(item->reason, OUT_RSN_SIZE, "abort");
        safe_strcpy(item->classification, OUT_CLS_SIZE, "closed");
    }

    int rpt_tmp = 0;

    if (sctpinit_conf.record_ttl)
        rpt_tmp += snprintf(item->report+rpt_tmp, OUT_RPT_SIZE-rpt_tmp,
            "[ttl=%d]", recved->parsed.ip_ttl);
    if (sctpinit_conf.record_ipid && recved->parsed.src_ip.version==4)
        rpt_tmp += snprintf(item->report+rpt_tmp, OUT_RPT_SIZE-rpt_tmp,
            "[ipid=%d]", recved->parsed.ip_v4_id);
}

void sctpinit_timeout(
    uint64_t entropy,
    struct ScanTmEvent *event,
    struct OutputItem *item,
    struct stack_t *stack,
    struct FHandler *handler)
{
    item->level = Output_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "closed");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "timeout");
}

struct ScanModule SctpInitScan = {
    .name                = "sctp-init",
    .required_probe_type = 0,
    .support_timeout     = 1,
    .params              = sctpinit_parameters,
    .bpf_filter          = "sctp && (sctp[12]==2 || sctp[12]==6)", /*sctp init or init ack*/
    .desc =
        "SctpInitScan sends an SCTP INIT packet(chunk) to target port. Expect an "
        "INIT ACK response to believe the port is open or an ABORT for closed in "
        "SCTP protocol.",

    .global_init_cb          = &scan_global_init_nothing,
    .transmit_cb             = &sctpinit_transmit,
    .validate_cb             = &sctpinit_validate,
    .handle_cb               = &sctpinit_handle,
    .timeout_cb              = &sctpinit_timeout,
    .poll_cb                 = &scan_poll_nothing,
    .close_cb                = &scan_close_nothing,
};
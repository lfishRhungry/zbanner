#include "../probe-modules.h"

#include <string.h>
#include <time.h>

#include "../../util-data/safe-string.h"

/*for internal x-ref*/
extern Probe LzrDnsProbe;

// question: baidu.com
static char lzr_dns_payload[] = "\x00\x23" /*head*/
                                "\x69\x22" /*ID*/
                                "\x01\x00" /*Flags*/
                                "\x00\x01" /*question count*/
                                "\x00\x00" /*answer count*/
                                "\x00\x00" /*authority RRs*/
                                "\x00\x00" /*additional RRs*/
                                "\x05"     /*len of `baidu`*/
                                "\x62\x61\x69\x64\x75"
                                "\x03" /*len of `com`*/
                                "\x63\x6f\x6d"
                                "\x00"     /*"."*/
                                "\x00\x01" /*A record*/
                                "\x00\x01" /*TCP/IP addr*/
    ;

// question: stackoverflow.com
//  static char lzr_dns_payload_origin[] =
//  "\x00\x23"    /*ID*/
//  "\x69\x22"    /*ID*/
//  "\x01\x00"    /*Flags*/
//  "\x00\x01"    /*question count*/
//  "\x00\x00"    /*answer count*/
//  "\x00\x00"    /*authority RRs*/
//  "\x00\x00"    /*additional RRs*/
//  "\x0d"        /*len of `stackoverflow`*/
//  "\x73\x74\x61\x63\x6b\x6f\x76\x65\x72\x66\x6c\x6f\x77"
//  "\x03"        /*len of `com`*/
//  "\x63\x6f\x6d"
//  "\x00"        /*"."*/
//  "\x00\x01"    /*A record*/
//  "\x00\x01"    /*TCP/IP addr*/
//  ;

static size_t lzr_dns_make_payload(ProbeTarget   *target,
                                   unsigned char *payload_buf) {
    memcpy(payload_buf, lzr_dns_payload, sizeof(lzr_dns_payload) - 1);
    return sizeof(lzr_dns_payload) - 1;
}

static size_t lzr_dns_get_payload_length(ProbeTarget *target) {
    return sizeof(lzr_dns_payload) - 1;
}

static unsigned lzr_dns_handle_reponse(unsigned th_idx, ProbeTarget *target,
                                       const unsigned char *px,
                                       unsigned sizeof_px, OutItem *item) {
    if (safe_memmem(px, sizeof_px, "stackoverflow", strlen("stackoverflow"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "dns");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");
        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not dns");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

Probe LzrDnsProbe = {
    .name       = "lzr-dns",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = NULL,
    .desc = "LzrDns Probe sends an DNS request and identifies DNS service.",

    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &lzr_dns_make_payload,
    .get_payload_length_cb = &lzr_dns_get_payload_length,
    .handle_response_cb    = &lzr_dns_handle_reponse,
    .close_cb              = &probe_close_nothing,
};
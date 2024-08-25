#include <string.h>
#include <time.h>

#ifndef NOT_FOUND_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#include "probe-modules.h"
#include "../version.h"
#include "../util-data/safe-string.h"
#include "../util-data/data-convert.h"
#include "../util-data/fine-malloc.h"

/*for internal x-ref*/
extern Probe TlsHelloProbe;

static char tls_hello_payload[] =
    "\x16"                                 /*handshake*/
    "\x03\x01"                             /*TLSv1.0*/
    "\x00\x75"                             /*length 117*/
    "\x01"                                 /*client hello*/
    "\x00\x00\x71"                         /*length 113*/
    "\x03\x03"                             /*TLSv1.2*/
    "\x00\x00\x00\x00\x00\x00\x00\x00"     /*random*/
    "\x00\x00\x00\x00\x00\x00\x00\x00"     /*random*/
    "\x00\x00\x00\x00\x00\x00\x00\x00"     /*random*/
    "\x00\x00\x00\x00\x00\x00\x00\x00"     /*random*/
    "\x00"                                 /*session ID length 0*/
    "\x00\x1a"                             /*cipher suites lenght 26*/
    "\xc0\x2f"                             /*cipher suite*/
    "\xc0\x2b"                             /*cipher suite*/
    "\xc0\x11"                             /*cipher suite*/
    "\xc0\x07"                             /*cipher suite*/
    "\xc0\x13"                             /*cipher suite*/
    "\xc0\x09"                             /*cipher suite*/
    "\xc0\x14"                             /*cipher suite*/
    "\xc0\x0a"                             /*cipher suite*/
    "\x00\x05"                             /*cipher suite*/
    "\x00\x2f"                             /*cipher suite*/
    "\x00\x35"                             /*cipher suite*/
    "\xc0\x12"                             /*cipher suite*/
    "\x00\x0a"                             /*cipher suite*/
    "\x01"                                 /*compression methods length*/
    "\x00"                                 /*compression methods*/
    "\x00\x2e"                             /*extension length 46*/
    "\x00\x05\x00\x05\x01\x00\x00\x00\x00" /*ext status request*/
    "\x00\x0a\x00\x08\x00\x06\x00\x17\x00\x18\x00\x19" /*ext supported
                                                          groups*/
    "\x00\x0b\x00\x02\x01\x00"                         /*ext ec point formats*/
    "\x00\x0d\x00\x0a\x00\x08\x04\x01\x04\x03\x02\x01\x02\x03" /*ext
                                                                  signature
                                                                  algorithms*/
    "\xff\x01\x00\x01\x00" /*ext renegotiation info*/
    ;

struct TlsHello {
    unsigned banner : 1;
#ifndef NOT_FOUND_PCRE2
    char                *regex;
    size_t               regex_len;
    pcre2_code          *compiled_re;
    pcre2_match_context *match_ctx;
    unsigned             re_case_insensitive : 1;
    unsigned             re_include_newlines : 1;
#endif
};

static struct TlsHello tlshello_conf = {0};

static ConfRes SET_show_banner(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tlshello_conf.banner = parseBoolean(value);

    return Conf_OK;
}

#ifndef NOT_FOUND_PCRE2

static ConfRes SET_newlines(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tlshello_conf.re_include_newlines = parseBoolean(value);

    return Conf_OK;
}

static ConfRes SET_insensitive(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tlshello_conf.re_case_insensitive = parseBoolean(value);

    return Conf_OK;
}

static ConfRes SET_regex(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (tlshello_conf.compiled_re)
        pcre2_code_free(tlshello_conf.compiled_re);
    if (tlshello_conf.match_ctx)
        pcre2_match_context_free(tlshello_conf.match_ctx);

    tlshello_conf.regex_len = strlen(value);
    if (tlshello_conf.regex_len == 0) {
        LOG(LEVEL_ERROR, "Invalid regex.\n");
        return Conf_ERR;
    }

    int        pcre2_errcode;
    PCRE2_SIZE pcre2_erroffset;
    tlshello_conf.regex = STRDUP(value);
    tlshello_conf.compiled_re =
        pcre2_compile((PCRE2_SPTR)tlshello_conf.regex, PCRE2_ZERO_TERMINATED,
                      tlshello_conf.re_case_insensitive       ? PCRE2_CASELESS
                      : 0 | tlshello_conf.re_include_newlines ? PCRE2_DOTALL
                                                              : 0,
                      &pcre2_errcode, &pcre2_erroffset, NULL);

    if (!tlshello_conf.compiled_re) {
        LOG(LEVEL_ERROR, "Regex compiled failed.\n");
        return Conf_ERR;
    }

    tlshello_conf.match_ctx = pcre2_match_context_create(NULL);
    if (!tlshello_conf.match_ctx) {
        LOG(LEVEL_ERROR, "Regex allocates match_ctx failed.\n");
        return Conf_ERR;
    }

    pcre2_set_match_limit(tlshello_conf.match_ctx, 100000);

#ifdef pcre2_set_depth_limit
    // Changed name in PCRE2 10.30. PCRE2 uses macro definitions for function
    // names, so we don't have to add this to configure.ac.
    pcre2_set_depth_limit(tlshello_conf.match_ctx, 10000);
#else
    pcre2_set_recursion_limit(tlshello_conf.match_ctx, 10000);
#endif

    return Conf_OK;
}

#endif

static ConfParam tlshello_parameters[] = {
    {"banner",
     SET_show_banner,
     Type_BOOL,
     {0},
     "Show normalized banner in results."},

#ifndef NOT_FOUND_PCRE2
    {"regex",
     SET_regex,
     Type_NONE,
     {0},
     "Specifies a regex and sets matched response data as successed instead of"
     " reporting all results matched in protocol.\n"
     "NOTE: TlsHello only match the regex while it gets a ServerHello in type "
     "of HANDSHAKE."},
    {"case-insensitive",
     SET_insensitive,
     Type_BOOL,
     {"insensitive", 0},
     "Whether the specified regex is case-insensitive or not."},
    {"include-newlines",
     SET_newlines,
     Type_BOOL,
     {"include-newline", "newline", "newlines", 0},
     "Whether the specified regex contains newlines."},
#endif

    {0}};

static bool tlshello_init(const XConf *xconf) {
    /*fill the random bytes in payload*/
    unsigned r;
    srand((unsigned)time(NULL));
    char *p = tls_hello_payload + 11; /*Now it's Random in Handshake Protocol*/
    for (unsigned i = 0; i < 32 / 4; i++) {
        r = rand();
        U32_TO_BE((unsigned char *)p, r);
        p += 4;
    }

    return true;
}

static size_t tlshello_make_payload(ProbeTarget   *target,
                                    unsigned char *payload_buf) {
    memcpy(payload_buf, tls_hello_payload, sizeof(tls_hello_payload) - 1);
    return sizeof(tls_hello_payload) - 1;
}

static size_t tlshello_get_payload_length(ProbeTarget *target) {
    return sizeof(tls_hello_payload) - 1;
}

static unsigned tlshello_handle_reponse(unsigned th_idx, ProbeTarget *target,
                                        const unsigned char *px,
                                        unsigned sizeof_px, OutItem *item) {

    if (tlshello_conf.banner) {
        dach_append_normalized(&item->report, "banner", px, sizeof_px);
    }

    if (sizeof_px < 3) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "not TLS");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "protocol not matched");
        /*no further info*/
        return 0;
    }

    if (safe_memmem(px, sizeof_px, "HTTPS", strlen("HTTPS"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "maybe TLS");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "protocol matched https");
        /*no further info*/
        return 0;
    }

    /**
     * NOTE: We should only recv HANDSHAKE or ALERT
     */
    // http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/
    //  Record Type Values       dec      hex
    //  -------------------------------------
    //  CHANGE_CIPHER_SPEC        20     0x14
    //  ALERT                     21     0x15
    //  HANDSHAKE                 22     0x16
    //  APPLICATION_DATA          23     0x17
    // Version Values            dec     hex
    //  -------------------------------------
    //  SSL 3.0                   3,0  0x0300
    //  TLS 1.0                   3,1  0x0301
    //  TLS 1.1                   3,2  0x0302
    //  TLS 1.2                   3,3  0x0303
    //  TLS 1.3                   3,4  0x0304

    /*HANDSHAKE: we identify TLS version by field in Handshake Protocol*/
    if (px[0] == 0x16 && px[1] == 0x03 && px[2] >= 0x00 && px[2] <= 0x04 &&
        sizeof_px >= 11 && px[9] == 0x03) {
        if (px[10] == 0x00) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "SSLv3.0");
        } else if (px[10] == 0x01) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.0");
        } else if (px[10] == 0x02) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.1");
        } else if (px[10] == 0x03) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.2");
        } else {
            /**
             * 1. TLSv1.3 cannot be identified in this field.
             * 2. Our current probe cannot get normal response from TLSv1.3.
             */
            item->level = OUT_FAILURE;
            safe_strcpy(item->classification, OUT_CLS_SIZE, "not TLS");
            safe_strcpy(item->reason, OUT_RSN_SIZE, "protocol not matched");
            /*no further info*/
            return 0;
        }

        item->level = OUT_SUCCESS;
        safe_strcpy(item->reason, OUT_RSN_SIZE, "protocol matched");
        dach_append_normalized(&item->report, "type", "handshake",
                               sizeof("handshake") - 1);

        /*we can do further regex matching here*/
#ifndef NOT_FOUND_PCRE2

        if (tlshello_conf.compiled_re) {
            pcre2_match_data *match_data;
            int               rc;

            match_data = pcre2_match_data_create_from_pattern(
                tlshello_conf.compiled_re, NULL);
            if (!match_data) {
                LOG(LEVEL_ERROR, "cannot allocate match_data when matching.\n");
                item->no_output = 1;
                return 0;
            }

            rc = pcre2_match(tlshello_conf.compiled_re, (PCRE2_SPTR8)px,
                             (int)sizeof_px, 0, 0, match_data,
                             tlshello_conf.match_ctx);

            /*matched one. ps: "offset is too small" means successful, too*/
            if (rc >= 0) {
                item->level = OUT_SUCCESS;
                safe_strcpy(item->reason, OUT_RSN_SIZE, "regex matched");
            } else {
                item->level = OUT_FAILURE;
                safe_strcpy(item->reason, OUT_RSN_SIZE, "regex not matched");
            }

            pcre2_match_data_free(match_data);
        }
#endif

        return 0;

    } else if (px[0] == 0x15 && px[1] == 0x03 && sizeof_px >= 7) {
        if (px[10] == 0x00) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "SSLv3.0");
        } else if (px[10] == 0x01) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.0");
        } else if (px[10] == 0x02) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.1");
        } else if (px[10] == 0x03) {
            /**
             * NOTE: (Kludge)
             * In fast and practice, our probe can support normal TLS from
             * version 3.0 to version 1.2 .
             * If we got a `protocol version` alert from version 1.2, we can
             * infer that the server only support version 1.3 .
             */
            if (px[6] == 70) { /*ALERT DESC: Protocol Version*/
                safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.3");
            } else {
                safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.2");
            }
        } else {
            /**
             * 1. TLSv1.3 cannot be identified in this field.
             * 2. Our current probe cannot get normal response from TLSv1.3.
             */
            item->level = OUT_FAILURE;
            safe_strcpy(item->classification, OUT_CLS_SIZE, "not TLS");
            safe_strcpy(item->reason, OUT_RSN_SIZE, "protocol not matched");
            /*no further info*/
            return 0;
        }
#ifndef NOT_FOUND_PCRE2

        if (tlshello_conf.compiled_re) {
            item->level = OUT_FAILURE;
            safe_strcpy(item->reason, OUT_RSN_SIZE, "regex not matched");
        }
#endif

        item->level = OUT_SUCCESS;
        safe_strcpy(item->reason, OUT_RSN_SIZE, "protocol matched");
        dach_append_normalized(&item->report, "type", "alert",
                               sizeof("alert") - 1);
        dach_printf(&item->report, "level", true, "%u", px[5]);
        dach_printf(&item->report, "desc", true, "%u", px[6]);

        /*we can do further regex matching here*/

        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not TLS");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "protocol not matched");

    return 0;
}

static unsigned tlshello_handle_timeout(ProbeTarget *target, OutItem *item) {
    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not TLS");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "no response");
    return 0;
}

Probe TlsHelloProbe = {
    .name       = "tlshello",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = tlshello_parameters,
    .desc = "TlsHello Probe sends an simple universal TLSv1.2 ClientHello and "
            "gets the first response from target port. It tries to identify if "
            "the service is TLS/SSL and check the TLS/SSL version. Further "
            "more, we can set regex to match some text from the response. This "
            "helps us to find some interesting devices or upper-layer protocol "
            "from the cert or domains of the response.\n"
            "NOTE1: TlsHello is TCP type of probe with just one payload so "
            "that it could work in very high scan rate. We could use JARM "
            "probe which has 10 payloads to get more info about TLS/SSL itself "
            "or we can use TlsState probe which is in type of STATE to get "
            "info about upper-layer service like HTTPS.\n"
            "NOTE2: TlsHello is designed to prioritize compatibility with "
            "older TLS/SSL version. That's why it uses a ClientHello with "
            "version from TLSv1.0 to TLSv1.2 as payload. Because of that, it "
            "cannot get more info if the target server supports only TLSv1.3 "
            "which is very rare. I think it can be fixed later by some way but "
            "I'm too busy while creating the probe.",

    .init_cb               = &tlshello_init,
    .make_payload_cb       = &tlshello_make_payload,
    .get_payload_length_cb = &tlshello_get_payload_length,
    .handle_response_cb    = &tlshello_handle_reponse,
    .handle_timeout_cb     = &tlshello_handle_timeout,
    .close_cb              = &probe_close_nothing,
};
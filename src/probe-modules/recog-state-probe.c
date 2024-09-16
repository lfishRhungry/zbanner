#ifndef NOT_FOUND_PCRE2

#include <string.h>

#include "probe-modules.h"
#include "../proto/proto-http-maker.h"
#include "../proto/proto-http-parser.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../crypto/crypto-base64.h"
#include "../crypto/crypto-nmapprobe.h"
#include "../recog/recog-fingerprint.h"

struct RecogStateConf {
    unsigned char   *hello;
    size_t           hello_len;
    char            *xml_filename;
    struct Recog_FP *recog_fp;
    unsigned         banner_while_regex : 1;
    unsigned         banner_if_fail     : 1;
    unsigned         unprefix           : 1;
    unsigned         unsuffix           : 1;
    unsigned         get_whole_response : 1;
};

static struct RecogStateConf recogstate_conf = {0};

static ConfRes SET_unsuffix(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recogstate_conf.unsuffix = parseBoolean(value);

    return Conf_OK;
}

static ConfRes SET_unprefix(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recogstate_conf.unprefix = parseBoolean(value);

    return Conf_OK;
}

static ConfRes SET_banner_if_fail(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recogstate_conf.banner_if_fail = parseBoolean(value);

    return Conf_OK;
}

static ConfRes SET_show_banner(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recogstate_conf.banner_while_regex = parseBoolean(value);

    return Conf_OK;
}

static ConfRes SET_get_whole_response(void *conf, const char *name,
                                      const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recogstate_conf.get_whole_response = parseBoolean(value);

    return Conf_OK;
}

static ConfRes SET_hello_string(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recogstate_conf.hello);

    recogstate_conf.hello_len = strlen(value);
    if (recogstate_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "Invalid hello string.\n");
        return Conf_ERR;
    }
    recogstate_conf.hello = MALLOC(recogstate_conf.hello_len);
    memcpy(recogstate_conf.hello, value, recogstate_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_nmap(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recogstate_conf.hello);

    recogstate_conf.hello_len = strlen(value);
    if (recogstate_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "Invalid hello string in nmap probe format.\n");
        return Conf_ERR;
    }

    recogstate_conf.hello = CALLOC(1, recogstate_conf.hello_len);
    recogstate_conf.hello_len =
        nmapprobe_decode(value, recogstate_conf.hello_len,
                         recogstate_conf.hello, recogstate_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_base64(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recogstate_conf.hello);

    recogstate_conf.hello_len = strlen(value);
    if (recogstate_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "Invalid hello string in base64 format.\n");
        return Conf_ERR;
    }

    recogstate_conf.hello = CALLOC(1, recogstate_conf.hello_len);
    recogstate_conf.hello_len =
        base64_decode((char *)recogstate_conf.hello, recogstate_conf.hello_len,
                      value, recogstate_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recogstate_conf.hello);

    FILE *fp = fopen(value, "rb");
    if (fp == NULL) {
        LOG(LEVEL_ERROR, "Failed to open file %s.\n", value);
        return Conf_ERR;
    }

    /**
     * We may specify a large size file accidently, so limit the size by a buf.
     */
    unsigned char buf[PM_PAYLOAD_SIZE];
    size_t        bytes_read = fread(buf, 1, PM_PAYLOAD_SIZE, fp);
    if (bytes_read == 0) {
        LOG(LEVEL_ERROR, "Failed to read valid hello in file %s.\n", value);
        perror(value);
        fclose(fp);
        return Conf_ERR;
    }
    fclose(fp);

    recogstate_conf.hello_len = bytes_read;
    recogstate_conf.hello     = MALLOC(bytes_read);
    memcpy(recogstate_conf.hello, buf, bytes_read);

    return Conf_OK;
}

static ConfRes SET_recog_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recogstate_conf.xml_filename);

    recogstate_conf.xml_filename = STRDUP(value);

    return Conf_OK;
}

static ConfParam recogstate_parameters[] = {
    {"string",
     SET_hello_string,
     Type_NONE,
     {0},
     "Specifies a string and set it as hello data after decoded."
     " This will overwrite hello data set by other parameters."},
    {"base64-string",
     SET_hello_base64,
     Type_NONE,
     {"base64", 0},
     "Specifies a string in base64 format and set it as hello data after "
     "decoded."
     " This will overwrite hello data set by other parameters."},
    {"nmap-string",
     SET_hello_nmap,
     Type_NONE,
     {"nmap", 0},
     "Specifies a string in nmap probe format and set it as hello data after "
     "decoded."
     " This will overwrite hello data set by other parameters."},
    {"file",
     SET_hello_file,
     Type_NONE,
     {0},
     "Specifies a file and set the content of file as hello data."
     " This will overwrite hello data set by other parameters."},
    {"get-whole-response",
     SET_get_whole_response,
     Type_BOOL,
     {"whole", 0},
     "Get the whole response before connection timeout, not just the banner."},
    {"recog-xml",
     SET_recog_file,
     Type_NONE,
     {"xml", "xml-file", 0},
     "Specifies a xml file in Recog fingerprint format as the matching "
     "source."},
    {"banner",
     SET_show_banner,
     Type_BOOL,
     {0},
     "Show normalized banner after regex matching."},
    {"banner-if-fail",
     SET_banner_if_fail,
     Type_BOOL,
     {"banner-fail", "fail-banner", 0},
     "Show normalized banner in results if regex matching failed."},
    {"unprefix",
     SET_unprefix,
     Type_BOOL,
     {0},
     "Unprefix the '^' from the head of all regex. It's useful if we cannot "
     "extract exactly the proper part of string for matching."},
    {"unsuffix",
     SET_unsuffix,
     Type_BOOL,
     {0},
     "Unprefix the '$' from the tail of all regex. It's useful if we cannot "
     "extract exactly the proper part of string for matching."},

    {0}};

/*for internal x-ref*/
extern Probe RecogStateProbe;

static bool recogstate_init(const XConf *xconf) {
    if (recogstate_conf.hello == NULL || recogstate_conf.hello_len == 0) {
        recogstate_conf.hello     = NULL;
        recogstate_conf.hello_len = 0;
        LOG(LEVEL_ERROR,
            "RecogStateProbe: No hello data specified, just wait response.\n");
    }

    if (recogstate_conf.xml_filename == NULL ||
        recogstate_conf.xml_filename[0] == '\0') {
        LOG(LEVEL_ERROR,
            "RecogStateProbe: No Recog fingerprint xml file specified.\n");
        return false;
    }

    recogstate_conf.recog_fp =
        load_recog_fp(recogstate_conf.xml_filename, recogstate_conf.unprefix,
                      recogstate_conf.unsuffix);
    if (recogstate_conf.recog_fp == NULL) {
        LOG(LEVEL_ERROR, "Failed to load recog xml file %s.\n",
            recogstate_conf.xml_filename);
        return Conf_ERR;
    }

    return true;
}

static void recogstate_make_hello(DataPass *pass, ProbeState *state,
                                  ProbeTarget *target) {
    datapass_set_data(pass, recogstate_conf.hello, recogstate_conf.hello_len,
                      false);
}

static unsigned recogstate_parse_response(DataPass *pass, ProbeState *state,
                                          OutConf *out, ProbeTarget *target,
                                          const unsigned char *px,
                                          unsigned             sizeof_px) {
    if (state->state)
        return 0;

    if (!recogstate_conf.get_whole_response) {
        state->state   = 1;
        pass->is_close = 1;
    }

    OutItem item = {
        .target.ip_proto  = target->target.ip_proto,
        .target.ip_them   = target->target.ip_them,
        .target.ip_me     = target->target.ip_me,
        .target.port_them = target->target.port_them,
        .target.port_me   = target->target.port_me,
    };

    const char *match_res =
        match_recog_fp(recogstate_conf.recog_fp, px, sizeof_px);

    if (match_res) {
        item.level = OUT_SUCCESS;
        safe_strcpy(item.classification, OUT_CLS_SIZE, "matched");
        dach_append(&item.report, "result", match_res, strlen(match_res),
                    LinkType_String);

        if (recogstate_conf.banner_while_regex) {
            dach_append_normalized(&item.report, "banner", px, sizeof_px,
                                   LinkType_String);
        }
    } else {
        item.level = OUT_FAILURE;
        safe_strcpy(item.classification, OUT_CLS_SIZE, "not matched");

        if (recogstate_conf.banner_while_regex ||
            recogstate_conf.banner_if_fail) {
            dach_append_normalized(&item.report, "banner", px, sizeof_px,
                                   LinkType_String);
        }
    }

    output_result(out, &item);

    return 0;
}

static void recogstate_close() {
    FREE(recogstate_conf.hello);
    recogstate_conf.hello_len = 0;

    if (recogstate_conf.recog_fp) {
        free_recog_fp(recogstate_conf.recog_fp);
        recogstate_conf.recog_fp = NULL;
    }
}

Probe RecogStateProbe = {
    .name       = "recog-state",
    .type       = ProbeType_STATE,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .hello_wait = 0,
    .params     = recogstate_parameters,
    .short_desc = "Try to match Recog fingerprints in stateful TCP scan.",
    .desc =
        "RecogStateProbe is the stateful version of RecogProbe. RecogStateProbe"
        " use static content set by user as hello data and match the "
        "response with specified Recog fingerprints. It's a proof of concept "
        "for"
        " service version detection.\n"
        "NOTE1: Recog fingerprints are adapted for specific part of response "
        "data"
        " like html title, http cookie and etc. But RecogProbe doesn't prepare"
        " specific type of probes so that it cannot extract some part of data. "
        "However, we could ignore position parameters of regex like '^' and '$'"
        " by probe params to match the whole response. This is enough and "
        "useful"
        " to solve most cases. Implement your own probes if you want a more "
        "accurate results.\n"
        "NOTE2: I found the order of fingerprints in recog xml file would "
        "affect"
        " the identidying result because our probe just output the first "
        "matched"
        " result.\n"
        "Dependencies: PCRE2, LibXml2.",

    .init_cb           = &recogstate_init,
    .conn_init_cb      = &probe_conn_init_nothing,
    .make_hello_cb     = &recogstate_make_hello,
    .parse_response_cb = &recogstate_parse_response,
    .conn_close_cb     = &probe_conn_close_nothing,
    .close_cb          = &recogstate_close,
};

#endif /*ifndef NOT_FOUND_PCRE2*/
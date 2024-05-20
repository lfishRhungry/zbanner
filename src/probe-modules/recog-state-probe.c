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
    unsigned char          *hello;
    size_t                  hello_len;
    char                   *xml_filename;
    struct Recog_FP        *recog_fp;
    unsigned                report_while_fail:1;
    unsigned                unprefix:1;
    unsigned                unsuffix:1;
    unsigned                get_whole_response:1;
};

static struct RecogStateConf recogstate_conf = {0};

static enum Config_Res SET_unsuffix(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recogstate_conf.unsuffix = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_unprefix(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recogstate_conf.unprefix = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_report(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recogstate_conf.report_while_fail = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_get_whole_response(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recogstate_conf.get_whole_response = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_hello_string(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (recogstate_conf.hello)
        free(recogstate_conf.hello);

    recogstate_conf.hello_len = strlen(value);
    if (recogstate_conf.hello_len==0) {
        LOG(LEVEL_ERROR, "FAIL: Invalid hello string.\n");
        return CONF_ERR;
    }
    recogstate_conf.hello = MALLOC(recogstate_conf.hello_len);
    memcpy(recogstate_conf.hello, value, recogstate_conf.hello_len);

    return CONF_OK;
}

static enum Config_Res SET_hello_nmap(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (recogstate_conf.hello)
        free(recogstate_conf.hello);

    recogstate_conf.hello_len = strlen(value);
    if (recogstate_conf.hello_len==0) {
        LOG(LEVEL_ERROR, "FAIL: Invalid hello string in nmap probe format.\n");
        return CONF_ERR;
    }

    recogstate_conf.hello     = CALLOC(1, recogstate_conf.hello_len);
    recogstate_conf.hello_len = nmapprobe_decode(value,
        recogstate_conf.hello_len, recogstate_conf.hello, recogstate_conf.hello_len);

    return CONF_OK;
}

static enum Config_Res SET_hello_base64(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (recogstate_conf.hello)
        free(recogstate_conf.hello);

    recogstate_conf.hello_len = strlen(value);
    if (recogstate_conf.hello_len==0) {
        LOG(LEVEL_ERROR, "FAIL: Invalid hello string in base64 format.\n");
        return CONF_ERR;
    }

    recogstate_conf.hello     = CALLOC(1, recogstate_conf.hello_len);
    recogstate_conf.hello_len = base64_decode((char *)recogstate_conf.hello,
        recogstate_conf.hello_len, value, recogstate_conf.hello_len);

    return CONF_OK;
}

static enum Config_Res SET_hello_file(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (recogstate_conf.hello)
        free(recogstate_conf.hello);
    
    FILE *fp = fopen(value, "rb");
    if (fp==NULL) {
        LOG(LEVEL_ERROR, "[-]Failed to open file %s.\n", value);
        return CONF_ERR;
    }

    /**
     * We may specify a large size file accidently, so limit the size by a buf.
    */
    unsigned char buf[PROBE_PAYLOAD_MAX_LEN];
    size_t bytes_read = fread(buf, 1, PROBE_PAYLOAD_MAX_LEN, fp);
    if (bytes_read==0) {
        LOG(LEVEL_ERROR, "[-]Failed to read valid hello in file %s.\n", value);
        perror(value);
        fclose(fp);
        return CONF_ERR;
    }
    fclose(fp);


    recogstate_conf.hello_len = bytes_read;
    recogstate_conf.hello     = MALLOC(bytes_read);
    memcpy(recogstate_conf.hello, buf, bytes_read);

    return CONF_OK;
}

static enum Config_Res SET_recog_file(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (recogstate_conf.xml_filename)
        free(recogstate_conf.xml_filename);
    
    recogstate_conf.xml_filename = STRDUP(value);

    return CONF_OK;
}

static struct ConfigParam recogstate_parameters[] = {
    {
        "string",
        SET_hello_string,
        F_NONE,
        {0},
        "Specifies a string and set it as hello data after decoded."
        " This will overwrite hello data set by other parameters."
    },
    {
        "base64-string",
        SET_hello_base64,
        F_NONE,
        {"base64", 0},
        "Specifies a string in base64 format and set it as hello data after decoded."
        " This will overwrite hello data set by other parameters."
    },
    {
        "nmap-string",
        SET_hello_nmap,
        F_NONE,
        {"nmap", 0},
        "Specifies a string in nmap probe format and set it as hello data after decoded."
        " This will overwrite hello data set by other parameters."
    },
    {
        "file",
        SET_hello_file,
        F_NONE,
        {0},
        "Specifies a file and set the content of file as hello data."
        " This will overwrite hello data set by other parameters."
    },
    {
        "get-whole-response",
        SET_get_whole_response,
        F_BOOL,
        {"whole", 0},
        "Get the whole response before connection timeout, not just the banner."
    },
    {
        "recog-xml",
        SET_recog_file,
        F_NONE,
        {"xml", "xml-file",0},
        "Specifies a xml file in Recog fingerprint format as the matching source."
    },
    {
        "report",
        SET_report,
        F_BOOL,
        {0},
        "Report response data if matching failed."
    },
    {
        "unprefix",
        SET_unprefix,
        F_BOOL,
        {0},
        "Unprefix the '^' from the head of all regex. It's useful if we cannot "
        "extract exactly the proper part of string for matching."
    },
    {
        "unsuffix",
        SET_unsuffix,
        F_BOOL,
        {0},
        "Unprefix the '$' from the tail of all regex. It's useful if we cannot "
        "extract exactly the proper part of string for matching."
    },
    
    {0}
};

/*for internal x-ref*/
extern struct ProbeModule RecogStateProbe;

static bool
recogstate_global_init(const struct Xconf *xconf)
{
    if (recogstate_conf.hello==NULL || recogstate_conf.hello_len==0) {
        recogstate_conf.hello     = NULL;
        recogstate_conf.hello_len = 0;
        LOG(LEVEL_ERROR, "[-]RecogStateProbe: No hello data specified, just wait response.\n");
    }

    if (recogstate_conf.xml_filename==NULL || recogstate_conf.xml_filename[0]=='\0') {
        LOG(LEVEL_ERROR, "[-]RecogStateProbe: No Recog fingerprint xml file specified.\n");
        return false;
    }
    
    recogstate_conf.recog_fp = load_recog_fp(recogstate_conf.xml_filename,
        recogstate_conf.unprefix, recogstate_conf.unsuffix);
    if (recogstate_conf.recog_fp==NULL) {
        LOG(LEVEL_ERROR, "[-]Failed to load recog xml file %s.\n", recogstate_conf.xml_filename);
        return CONF_ERR;
    }


    return true;
}

static void
recogstate_make_hello(
    struct DataPass *pass,
    struct ProbeState *state,
    struct ProbeTarget *target)
{
    datapass_set_data(pass, recogstate_conf.hello, recogstate_conf.hello_len, 0);
}

static unsigned
recogstate_parse_response(
    struct DataPass *pass,
    struct ProbeState *state,
    struct Output *out,
    struct ProbeTarget *target,
    const unsigned char *px,
    unsigned sizeof_px)
{
    if (state->state) return 0;

    if (!recogstate_conf.get_whole_response) {
        state->state   = 1;
        pass->is_close = 1;
    }

    struct OutputItem item = {
        .ip_them   = target->ip_them,
        .ip_me     = target->ip_me,
        .port_them = target->port_them,
        .port_me   = target->port_me,
    };

    const char *match_res = match_recog_fp(recogstate_conf.recog_fp, px, sizeof_px);

    if (match_res) {
        item.level = Output_SUCCESS;
        safe_strcpy(item.classification, OUTPUT_CLS_SIZE, "matched");
        dach_append(&item.report, "result", match_res, DACH_AUTO_LEN);
    } else {
        item.level = Output_FAILURE;
        safe_strcpy(item.classification, OUTPUT_CLS_SIZE, "not matched");

        if (recogstate_conf.report_while_fail) {
            dach_append_normalized(&item.report, "banner", px, sizeof_px);
        }
    }

    output_result(out, &item);

    return 0;
}

static void
recogstate_close()
{
    if (recogstate_conf.hello) {
        free(recogstate_conf.hello);
        recogstate_conf.hello = NULL;
    }
    recogstate_conf.hello_len = 0;

    if (recogstate_conf.recog_fp) {
        free_recog_fp(recogstate_conf.recog_fp);
        recogstate_conf.recog_fp = NULL;
    }

}

struct ProbeModule RecogStateProbe = {
    .name       = "recog-state",
    .type       = ProbeType_STATE,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .hello_wait = 0,
    .params     = recogstate_parameters,
    .desc =
        "RecogStateProbe is the stateful version of RecogProbe. RecogStateProbe"
        " use static content set by user as hello data and match the "
        "response with specified Recog fingerprints. It's a proof of concept for"
        " service version detection.\n"
        "NOTE1: Recog fingerprints are adapted for specific part of response data"
        " like html title, http cookie and etc. But RecogProbe doesn't prepare"
        " specific type of probes so that it cannot extract some part of data. "
        "However, we could ignore position parameters of regex like '^' and '$'"
        " by probe params to match the whole response. This is enough and useful"
        " to solve most cases. Implement your own probes if you want a more "
        "accurate results.\n"
        "NOTE2: I found the order of fingerprints in recog xml file would affect"
        " the identidying result because our probe just output the first matched"
        " result.\n"
        "Dependencies: PCRE2, LibXml2.",
    .global_init_cb                    = &recogstate_global_init,
    .conn_init_cb                      = &probe_conn_init_nothing,
    .make_hello_cb                     = &recogstate_make_hello,
    .parse_response_cb                 = &recogstate_parse_response,
    .conn_close_cb                     = &probe_conn_close_nothing,
    .close_cb                          = &recogstate_close,
};

#endif /*ifndef NOT_FOUND_PCRE2*/
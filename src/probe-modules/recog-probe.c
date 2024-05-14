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

struct RecogConf {
    unsigned char          *hello;
    size_t                  hello_len;
    char                   *xml_filename;
    struct Recog_FP        *recog_fp;
    unsigned                report_while_fail:1;
    unsigned                unprefix:1;
    unsigned                unsuffix:1;
};

static struct RecogConf recog_conf = {0};

static enum Config_Res SET_unsuffix(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recog_conf.unsuffix = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_unprefix(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recog_conf.unprefix = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_report(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recog_conf.report_while_fail = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_hello_string(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (recog_conf.hello)
        free(recog_conf.hello);

    recog_conf.hello_len = strlen(value);
    if (recog_conf.hello_len==0) {
        LOG(LEVEL_ERROR, "FAIL: Invalid hello string.\n");
        return CONF_ERR;
    }
    recog_conf.hello = MALLOC(recog_conf.hello_len);
    memcpy(recog_conf.hello, value, recog_conf.hello_len);

    return CONF_OK;
}

static enum Config_Res SET_hello_nmap(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (recog_conf.hello)
        free(recog_conf.hello);

    recog_conf.hello_len = strlen(value);
    if (recog_conf.hello_len==0) {
        LOG(LEVEL_ERROR, "FAIL: Invalid hello string in nmap probe format.\n");
        return CONF_ERR;
    }

    recog_conf.hello     = CALLOC(1, recog_conf.hello_len);
    recog_conf.hello_len = nmapprobe_decode(value,
        recog_conf.hello_len, recog_conf.hello, recog_conf.hello_len);

    return CONF_OK;
}

static enum Config_Res SET_hello_base64(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (recog_conf.hello)
        free(recog_conf.hello);

    recog_conf.hello_len = strlen(value);
    if (recog_conf.hello_len==0) {
        LOG(LEVEL_ERROR, "FAIL: Invalid hello string in base64 format.\n");
        return CONF_ERR;
    }

    recog_conf.hello     = CALLOC(1, recog_conf.hello_len);
    recog_conf.hello_len = base64_decode((char *)recog_conf.hello,
        recog_conf.hello_len, value, recog_conf.hello_len);

    return CONF_OK;
}

static enum Config_Res SET_hello_file(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (recog_conf.hello)
        free(recog_conf.hello);
    
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


    recog_conf.hello_len = bytes_read;
    recog_conf.hello     = MALLOC(bytes_read);
    memcpy(recog_conf.hello, buf, bytes_read);

    return CONF_OK;
}

static enum Config_Res SET_recog_file(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (recog_conf.xml_filename)
        free(recog_conf.xml_filename);
    
    recog_conf.xml_filename = STRDUP(value);

    return CONF_OK;
}

static struct ConfigParam recog_parameters[] = {
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
extern struct ProbeModule RecogProbe;

static bool
recog_global_init(const struct Xconf *xconf)
{
    if (recog_conf.hello==NULL || recog_conf.hello_len==0) {
        recog_conf.hello     = NULL;
        recog_conf.hello_len = 0;
        LOG(LEVEL_ERROR, "[-]RecogProbe: No hello data specified, just wait response.\n");
    }

    if (recog_conf.xml_filename==NULL || recog_conf.xml_filename[0]=='\0') {
        LOG(LEVEL_ERROR, "[-]RecogProbe: No Recog fingerprint xml file specified.\n");
        return false;
    }
    
    recog_conf.recog_fp = load_recog_fp(recog_conf.xml_filename,
        recog_conf.unprefix, recog_conf.unsuffix);
    if (recog_conf.recog_fp==NULL) {
        LOG(LEVEL_ERROR, "[-]Failed to load recog xml file %s.\n", recog_conf.xml_filename);
        return CONF_ERR;
    }

    return true;
}

static size_t
recog_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    if (recog_conf.hello==NULL || recog_conf.hello_len==0) {
        return 0;
    }

    memcpy(payload_buf, recog_conf.hello, recog_conf.hello_len);
    return recog_conf.hello_len;
}

static size_t
recog_get_payload_length(struct ProbeTarget *target)
{
    return recog_conf.hello_len;
}

static unsigned
recog_handle_response(
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    if (sizeof_px==0) {
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "no service");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "timeout");
        item->level = Output_FAILURE;
        return 0;
    }

    const char *match_res = match_recog_fp(recog_conf.recog_fp, px, sizeof_px);

    if (match_res) {
        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "success");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "matched");
        snprintf(item->report, OUTPUT_RPT_LEN, "%s", match_res);
    } else {
        item->level = Output_FAILURE;
        safe_strcpy(item->classification, OUTPUT_CLS_LEN, "fail");
        safe_strcpy(item->reason, OUTPUT_RSN_LEN, "not matched");

        if (recog_conf.report_while_fail) {
            normalize_string(px, sizeof_px, item->report, OUTPUT_RPT_LEN);
        }
    }

    return 0;
}

static void
recog_close()
{
    if (recog_conf.hello) {
        free(recog_conf.hello);
        recog_conf.hello = NULL;
    }
    recog_conf.hello_len = 0;

    if (recog_conf.recog_fp) {
        free_recog_fp(recog_conf.recog_fp);
        recog_conf.recog_fp = NULL;
    }

}

struct ProbeModule RecogProbe = {
    .name       = "recog",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = recog_parameters,
    .desc =
        "RecogProbe use static content set by user as hello data and match the "
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
    .global_init_cb                    = &recog_global_init,
    .make_payload_cb                   = &recog_make_payload,
    .get_payload_length_cb             = &recog_get_payload_length,
    .validate_response_cb              = NULL,
    .handle_response_cb                = &recog_handle_response,
    .close_cb                          = &recog_close,
};

#endif /*ifndef NOT_FOUND_PCRE2*/
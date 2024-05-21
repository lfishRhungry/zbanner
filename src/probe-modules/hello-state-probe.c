#include <string.h>

#ifndef NOT_FOUND_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#include "probe-modules.h"
#include "../proto/proto-http-maker.h"
#include "../proto/proto-http-parser.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../crypto/crypto-base64.h"
#include "../crypto/crypto-nmapprobe.h"

struct HelloStateConf {
    unsigned char          *hello;
    size_t                  hello_len;
#ifndef NOT_FOUND_PCRE2
    char                   *regex;
    size_t                  regex_len;
    pcre2_code             *compiled_re;
    pcre2_match_context    *match_ctx;
    unsigned                re_case_insensitive:1;
    unsigned                re_include_newlines:1;
    unsigned                match_whole_response:1;
    unsigned                report_while_regex:1;
#endif
    unsigned                get_whole_response:1;
};

static struct HelloStateConf hellostate_conf = {0};

static enum Config_Res SET_get_whole_response(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.get_whole_response = parseBoolean(value);

    return CONF_OK;
}

#ifndef NOT_FOUND_PCRE2

static enum Config_Res SET_report(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.report_while_regex = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_match_whole_response(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.match_whole_response = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_newlines(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.re_include_newlines = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_insensitive(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.re_case_insensitive = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_regex(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (hellostate_conf.compiled_re)
        pcre2_code_free(hellostate_conf.compiled_re);
    if (hellostate_conf.match_ctx)
        pcre2_match_context_free(hellostate_conf.match_ctx);

    hellostate_conf.regex_len = strlen(value);
    if (hellostate_conf.regex_len==0) {
        LOG(LEVEL_ERROR, "FAIL: Invalid regex.\n");
        return CONF_ERR;
    }

    int pcre2_errcode;
    PCRE2_SIZE pcre2_erroffset;
    hellostate_conf.regex = STRDUP(value);
    hellostate_conf.compiled_re = pcre2_compile(
        (PCRE2_SPTR)hellostate_conf.regex,
        PCRE2_ZERO_TERMINATED,
        hellostate_conf.re_case_insensitive?PCRE2_CASELESS:0 | hellostate_conf.re_include_newlines?PCRE2_DOTALL:0,
        &pcre2_errcode,
        &pcre2_erroffset,
        NULL);
    
    if (!hellostate_conf.compiled_re) {
        LOG(LEVEL_ERROR, "[-]Regex compiled failed.\n");
        return CONF_ERR;
    }

    hellostate_conf.match_ctx = pcre2_match_context_create(NULL);
    if (!hellostate_conf.match_ctx) {
        LOG(LEVEL_ERROR, "[-]Regex allocates match_ctx failed.\n");
        return CONF_ERR;
    }

    pcre2_set_match_limit(hellostate_conf.match_ctx, 100000);

#ifdef pcre2_set_depth_limit
            // Changed name in PCRE2 10.30. PCRE2 uses macro definitions for function
            // names, so we don't have to add this to configure.ac.
            pcre2_set_depth_limit(hellostate_conf.match_ctx, 10000);
#else
            pcre2_set_recursion_limit(hellostate_conf.match_ctx, 10000);
#endif


    return CONF_OK;
}

#endif

static enum Config_Res SET_hello_string(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (hellostate_conf.hello)
        free(hellostate_conf.hello);

    hellostate_conf.hello_len = strlen(value);
    if (hellostate_conf.hello_len==0) {
        LOG(LEVEL_ERROR, "FAIL: Invalid hello string.\n");
        return CONF_ERR;
    }
    hellostate_conf.hello = MALLOC(hellostate_conf.hello_len);
    memcpy(hellostate_conf.hello, value, hellostate_conf.hello_len);

    return CONF_OK;
}

static enum Config_Res SET_hello_nmap(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (hellostate_conf.hello)
        free(hellostate_conf.hello);

    hellostate_conf.hello_len = strlen(value);
    if (hellostate_conf.hello_len==0) {
        LOG(LEVEL_ERROR, "FAIL: Invalid hello string in nmap probe format.\n");
        return CONF_ERR;
    }

    hellostate_conf.hello     = CALLOC(1, hellostate_conf.hello_len);
    hellostate_conf.hello_len = nmapprobe_decode(value,
        hellostate_conf.hello_len, hellostate_conf.hello, hellostate_conf.hello_len);

    return CONF_OK;
}

static enum Config_Res SET_hello_base64(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (hellostate_conf.hello)
        free(hellostate_conf.hello);

    hellostate_conf.hello_len = strlen(value);
    if (hellostate_conf.hello_len==0) {
        LOG(LEVEL_ERROR, "FAIL: Invalid hello string in base64 format.\n");
        return CONF_ERR;
    }

    hellostate_conf.hello     = CALLOC(1, hellostate_conf.hello_len);
    hellostate_conf.hello_len = base64_decode((char *)hellostate_conf.hello,
        hellostate_conf.hello_len, value, hellostate_conf.hello_len);

    return CONF_OK;
}

static enum Config_Res SET_hello_file(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (hellostate_conf.hello)
        free(hellostate_conf.hello);
    
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


    hellostate_conf.hello_len = bytes_read;
    hellostate_conf.hello     = MALLOC(bytes_read);
    memcpy(hellostate_conf.hello, buf, bytes_read);

    return CONF_OK;
}

static struct ConfigParam hellostate_parameters[] = {
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

#ifndef NOT_FOUND_PCRE2
    {
        "regex",
        SET_regex,
        F_NONE,
        {0},
        "Specifies a regex and sets matched response data as successed instead of"
        " reporting all results."
    },
    {
        "case-insensitive",
        SET_insensitive,
        F_BOOL,
        {"insensitive", 0},
        "Whether the specified regex is case-insensitive or not."
    },
    {
        "include-newlines",
        SET_newlines,
        F_BOOL,
        {"include-newline", "newline", "newlines", 0},
        "Whether the specified regex contains newlines."
    },
    {
        "match-whole-response",
        SET_match_whole_response,
        F_BOOL,
        {"match-whole", 0},
        "Continue to match the whole response after matched previous content.\n"
        "NOTE: it works while using --get-whole-response."
    },
    {
        "report",
        SET_report,
        F_BOOL,
        {0},
        "Report response data after regex matching."
    },
#endif

    {
        "get-whole-response",
        SET_get_whole_response,
        F_BOOL,
        {"whole", 0},
        "Get the whole response before connection timeout, not just the banner."
    },
    
    {0}
};

/*for internal x-ref*/
extern struct ProbeModule HelloStateProbe;

static bool
hellostate_global_init(const struct Xconf *xconf)
{
    if (hellostate_conf.hello==NULL || hellostate_conf.hello_len==0) {
        hellostate_conf.hello     = NULL;
        hellostate_conf.hello_len = 0;
        LOG(LEVEL_ERROR, "[-]HelloStateProbe: No hello data specified, just wait response.\n");
    }

    return true;
}

static void
hellostate_make_hello(
    struct DataPass *pass,
    struct ProbeState *state,
    struct ProbeTarget *target)
{
    datapass_set_data(pass, hellostate_conf.hello, hellostate_conf.hello_len, 0);
}

static unsigned
hellostate_parse_response(
    struct DataPass *pass,
    struct ProbeState *state,
    struct Output *out,
    struct ProbeTarget *target,
    const unsigned char *px,
    unsigned sizeof_px)
{
    if (state->state) return 0;

    if (!hellostate_conf.get_whole_response) {
        state->state   = 1;
        pass->is_close = 1;
    }

    struct OutputItem item = {
        .ip_proto  = target->ip_proto,
        .ip_them   = target->ip_them,
        .ip_me     = target->ip_me,
        .port_them = target->port_them,
        .port_me   = target->port_me,
    };


#ifndef NOT_FOUND_PCRE2

    if (hellostate_conf.compiled_re) {
        pcre2_match_data *match_data;
        int rc;

        match_data = pcre2_match_data_create_from_pattern(hellostate_conf.compiled_re, NULL);
        if (!match_data) {
            LOG(LEVEL_ERROR, "FAIL: cannot allocate match_data when matching.\n");
            return 0;
        }

        rc = pcre2_match(hellostate_conf.compiled_re,
            (PCRE2_SPTR8)px, (int)sizeof_px,
            0, 0, match_data, hellostate_conf.match_ctx);

        /*matched one. ps: "offset is too small" means successful, too*/
        if (rc >= 0) {
            item.level = Output_SUCCESS;
            safe_strcpy(item.classification, OUTPUT_CLS_SIZE, "matched");

            if (!hellostate_conf.match_whole_response) {
                state->state   = 1;
                pass->is_close = 1;
            }

        } else {
            item.level = Output_FAILURE;
            safe_strcpy(item.classification, OUTPUT_CLS_SIZE, "not matched");
        }
        
        if (hellostate_conf.report_while_regex) {
            dach_append_normalized(&item.report, "banner", px, sizeof_px);
        }
        pcre2_match_data_free(match_data);
    } else {

#endif

        item.level = Output_SUCCESS;
        dach_append_normalized(&item.report, "banner", px, sizeof_px);

#ifndef NOT_FOUND_PCRE2
    }
#endif

    output_result(out, &item);

    return 0;
}

static void
hellostate_close()
{
    if (hellostate_conf.hello) {
        free(hellostate_conf.hello);
        hellostate_conf.hello = NULL;
    }
    hellostate_conf.hello_len = 0;

#ifndef NOT_FOUND_PCRE2
    if (hellostate_conf.regex) {
        free(hellostate_conf.regex);
        hellostate_conf.regex = NULL;
    }
    hellostate_conf.regex_len = 0;

    if (hellostate_conf.compiled_re) {
        pcre2_code_free(hellostate_conf.compiled_re);
        hellostate_conf.compiled_re = NULL;
    }

    if (hellostate_conf.match_ctx) {
        pcre2_match_context_free(hellostate_conf.match_ctx);
        hellostate_conf.match_ctx = NULL;
    }
#endif

}

struct ProbeModule HelloStateProbe = {
    .name       = "hello-state",
    .type       = ProbeType_STATE,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .hello_wait = 0,
    .params     = hellostate_parameters,
    .desc =
        "HelloStateProbe is the stateful version of HelloPorbe, it uses static"
        " content set by user as hello data and reports banner. It is used to "
        "test POC immediatly under stateful TCP connection and can work with "
        "services over TLS. We can set hello data in different format and set"
        " a regex to match the the first response(banner) or whole response "
        " as successed.\n"
        "NOTE: If no hello data was specified, HelloStateProbe would just wait "
        "banner(first packet with reponse).\n"
        "Dependencies: PCRE2 for regex.",
    .global_init_cb                    = &hellostate_global_init,
    .conn_init_cb                      = &probe_conn_init_nothing,
    .make_hello_cb                     = &hellostate_make_hello,
    .parse_response_cb                 = &hellostate_parse_response,
    .conn_close_cb                     = &probe_conn_close_nothing,
    .close_cb                          = &hellostate_close,
};
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

static const char
default_http_header[] =
"GET / HTTP/1.0\r\n"
"User-Agent: "XTATE_WITH_VERSION" "XTATE_GITHUB"\r\n"
"Accept: */*\r\n"
"\r\n"
;

static const char
host_fmt_ipv4[] = "%s";

static const char
host_fmt_ipv6[] = "[%s]";

struct HttpConf {
    /*IPv4*/
    char *request4;
    size_t req4_len;

    /*IPv6*/
    char *request6;
    size_t req6_len;

    /* Method */
    char *method;
    size_t method_length;

    /* URL */
    char *url;
    size_t url_length;

    /* Version */
    char *version;
    size_t version_length;

    /* Host */
    char *host;
    size_t host_length;

    /* User-Agent */
    char *user_agent;
    size_t user_agent_length;

    /* Payload after the header*/
    char *payload;
    size_t payload_length;

    /* Headers */
    struct {
        const char *name;
        char *value;
        size_t value_length;
    } headers[16];
    size_t headers_count;

    /* Cookies */
    struct {
        char *value;
        size_t value_length;
    } cookies[16];
    size_t cookies_count;

    /* Remove */
    struct {
        char *name;
    } remove[16];
    size_t remove_count;


#ifndef NOT_FOUND_PCRE2
    char                   *regex;
    size_t                  regex_len;
    pcre2_code             *compiled_re;
    pcre2_match_context    *match_ctx;
    unsigned                re_case_insensitive:1;
    unsigned                re_include_newlines:1;
    unsigned report_while_regex:1;
#endif
    /*dynamic set ip:port as Host field*/
    unsigned dynamic_host:1;
};

static struct HttpConf http_conf = {0};

#ifndef NOT_FOUND_PCRE2

static enum Config_Res SET_report(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    http_conf.report_while_regex = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_newlines(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    http_conf.re_include_newlines = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_insensitive(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    http_conf.re_case_insensitive = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_regex(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (http_conf.compiled_re)
        pcre2_code_free(http_conf.compiled_re);
    if (http_conf.match_ctx)
        pcre2_match_context_free(http_conf.match_ctx);

    http_conf.regex_len = strlen(value);
    if (http_conf.regex_len==0) {
        LOG(LEVEL_ERROR, "FAIL: Invalid regex.\n");
        return CONF_ERR;
    }

    int pcre2_errcode;
    PCRE2_SIZE pcre2_erroffset;
    http_conf.regex = STRDUP(value);
    http_conf.compiled_re = pcre2_compile(
        (PCRE2_SPTR)http_conf.regex,
        PCRE2_ZERO_TERMINATED,
        http_conf.re_case_insensitive?PCRE2_CASELESS:0 | http_conf.re_include_newlines?PCRE2_DOTALL:0,
        &pcre2_errcode,
        &pcre2_erroffset,
        NULL);
    
    if (!http_conf.compiled_re) {
        LOG(LEVEL_ERROR, "[-]Regex compiled failed.\n");
        return CONF_ERR;
    }

    http_conf.match_ctx = pcre2_match_context_create(NULL);
    if (!http_conf.match_ctx) {
        LOG(LEVEL_ERROR, "[-]Regex allocates match_ctx failed.\n");
        return CONF_ERR;
    }

    pcre2_set_match_limit(http_conf.match_ctx, 100000);

#ifdef pcre2_set_depth_limit
            // Changed name in PCRE2 10.30. PCRE2 uses macro definitions for function
            // names, so we don't have to add this to configure.ac.
            pcre2_set_depth_limit(http_conf.match_ctx, 10000);
#else
            pcre2_set_recursion_limit(http_conf.match_ctx, 10000);
#endif


    return CONF_OK;
}

#endif

static enum Config_Res SET_method(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (http_conf.method)
        free(http_conf.method);
    
    http_conf.method_length = strlen(value);
    http_conf.method = STRDUP(value);

    return CONF_OK;
}

static enum Config_Res SET_url(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (http_conf.url)
        free(http_conf.url);
    
    http_conf.url_length = strlen(value);
    http_conf.url = STRDUP(value);

    return CONF_OK;
}

static enum Config_Res SET_version(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (http_conf.version)
        free(http_conf.version);
    
    http_conf.version_length = strlen(value);
    http_conf.version = STRDUP(value);

    return CONF_OK;
}

static enum Config_Res SET_host(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (http_conf.host)
        free(http_conf.host);
    
    http_conf.host_length = strlen(value);
    http_conf.host = STRDUP(value);

    return CONF_OK;
}

static enum Config_Res SET_user_agent(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (http_conf.user_agent)
        free(http_conf.user_agent);
    
    http_conf.user_agent_length = strlen(value);
    http_conf.user_agent = STRDUP(value);

    return CONF_OK;
}

static enum Config_Res SET_payload(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (http_conf.payload)
        free(http_conf.payload);
    
    http_conf.payload_length = strlen(value);
    http_conf.payload = STRDUP(value);

    return CONF_OK;
}

static enum Config_Res SET_header(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);

    char            *newname;
    char            *newvalue;
    unsigned         name_length;
    size_t           value_length;
    /* 
     * allocate a new name 
     */
    name += 6;
    if (*name == '[') {
        /* Specified as: "--header[name] value" */
        while (ispunct(*name))
            name++;
        name_length = (unsigned)strlen(name);
        while (name_length && ispunct(name[name_length-1]))
            name_length--;
        newname = MALLOC(name_length+1);
        memcpy(newname, name, name_length+1);
        newname[name_length] = '\0';
    } else if (strchr(value, ':')) {
        /* Specified as: "--header Name:value" */
        name_length = INDEX_OF(value, ':');
        newname = MALLOC(name_length + 1);
        memcpy(newname, value, name_length + 1);
            
        /* Trim the value */
        value = value + name_length + 1;
        while (*value && isspace(*value & 0xFF))
            value++;

        /* Trim the name */
        while (name_length && isspace(newname[name_length-1]&0xFF))
            name_length--;
        newname[name_length] = '\0';
    } else {
        LOG(LEVEL_ERROR, "[-] --header needs both a name and value\n");
        LOG(LEVEL_ERROR, "    hint: \"--header Name:value\"\n");
        return CONF_ERR;
    }

    /* allocate new value */
    value_length = strlen(value);
    newvalue     = MALLOC(value_length+1);
    memcpy(newvalue, value, value_length+1);
    newvalue[value_length] = '\0';

    /* Add to our list of headers */
    if (http_conf.headers_count < ARRAY_SIZE(http_conf.headers)) {
        size_t x = http_conf.headers_count;
        http_conf.headers[x].name         = newname;
        http_conf.headers[x].value        = newvalue;
        http_conf.headers[x].value_length = value_length;
        http_conf.headers_count++;
    }

    return CONF_OK;
}

static enum Config_Res SET_cookie(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    char      *newvalue;
    size_t     value_length;

    /* allocate new value */
    value_length = strlen(value);
    newvalue = MALLOC(value_length+1);
    memcpy(newvalue, value, value_length+1);
    newvalue[value_length] = '\0';

    /* Add to our list of headers */
    if (http_conf.cookies_count < ARRAY_SIZE(http_conf.cookies)) {
        size_t x = http_conf.cookies_count;
        http_conf.cookies[x].value = newvalue;
        http_conf.cookies[x].value_length = value_length;
        http_conf.cookies_count++;
    }

    return CONF_OK;
}

static enum Config_Res SET_remove(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    char     *newvalue;
    size_t    value_length;

    /* allocate new value */
    value_length = strlen(value);
    newvalue = MALLOC(value_length+1);
    memcpy(newvalue, value, value_length+1);
    newvalue[value_length] = '\0';

    /* Add to our list of headers */
    if (http_conf.remove_count < ARRAY_SIZE(http_conf.remove)) {
        size_t x = http_conf.remove_count;
        http_conf.remove[x].name = newvalue;
        http_conf.remove_count++;
    }

    return CONF_OK;
}

static enum Config_Res SET_dynamic_host(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    http_conf.dynamic_host = parseBoolean(value);

    return CONF_OK;
}

static struct ConfigParam http_parameters[] = {
    {
        "method",
        SET_method,
        F_NONE,
        {0},
        "Changes the default `GET` method in http request line."
    },
    {
        "url",
        SET_url,
        F_NONE,
        {0},
        "Replaces the existing `/` url field in http request line."
    },
    {
        "version",
        SET_version,
        F_NONE,
        {"ver", 0},
        "Replaces the existing `HTTP/1.0` version field in http request line."
    },
    {
        "host",
        SET_host,
        F_NONE,
        {0},
        "Adds `Host` field to http request header."
    },
    {
        "dynamic-host",
        SET_dynamic_host,
        F_BOOL,
        {"ip-host", 0},
        "Sets(Adds) correspond IP address as `Host` field to http request header"
        " for different target e.g. `Host: 192.168.0.1`, `Host: [fe80::1]`."
    },
    {
        "user-agent",
        SET_user_agent,
        F_NONE,
        {"ua", 0},
        "Replaces existing `User-Agent` field in http request header.(highly "
        "recommended)"
    },
    {
        "payload",
        SET_payload,
        F_NONE,
        {0},
        "Adds a payload string after http request header. This will automatically"
        " add `--header Content-Length:LEN` field to match the length of the "
        "string.\n"
        "NOTE: We should add our own `--header Content-Type:TYPE` field to match"
        " the string. Presumably, we will also change the method to something "
        "like `--method POST`. Common `Content-Type` would be `application/x-www-"
        "form-urlencoded`, `application/json`, or `text/xml`."
    },
    {
        "cookie",
        SET_cookie,
        F_NONE,
        {0},
        "Adds a `Cookie` field to http request header even if other cookie fields"
        " exist."
    },
    {
        "header",
        SET_header,
        F_NONE,
        {0},
        "Replaces the existing http request header field or inserts a new one if"
        " the fields doesn't exist, given as a `name:value` pair. It cannot be "
        "used to replace the fields in the request line e.g. method, url and "
        "version.\n"
        "Example: `--header Accept:image/gif`, `--header[Accept] image/gif`\n"
    },
    {
        "remove",
        SET_remove,
        F_NONE,
        {0},
        "Removes the first field from the header that matches. We may need "
        "multiple times for fields like `Cookie` that can exist multiple times."
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
        "report",
        SET_report,
        F_BOOL,
        {0},
        "Report response data after regex matching."
    },
#endif

    {0}
};


/*for internal x-ref*/
extern struct ProbeModule HttpProbe;

static bool
http_global_init(const struct Xconf *xconf)
{
    http_conf.req4_len = sizeof(default_http_header);
    http_conf.request4 = MALLOC(http_conf.req4_len);
    memcpy(http_conf.request4, default_http_header, http_conf.req4_len);

    http_conf.req6_len = sizeof(default_http_header);
    http_conf.request6 = MALLOC(http_conf.req6_len);
    memcpy(http_conf.request6, default_http_header, http_conf.req6_len);

    if (http_conf.payload) {
        char lenstr[64];
        snprintf(lenstr, sizeof(lenstr), "%u", (unsigned)http_conf.payload_length);

        http_conf.req4_len = http_change_requestline(
            (unsigned char**)&http_conf.request4,
            http_conf.req4_len,
            (const unsigned char *)http_conf.payload,
            http_conf.payload_length,
            http_req_payload);

        http_conf.req4_len = http_change_field(
            (unsigned char**)&http_conf.request4,
            http_conf.req4_len,
            "Content-Length:",
            (const unsigned char *)lenstr,
            strlen(lenstr),
            http_field_replace);

        http_conf.req6_len = http_change_requestline(
            (unsigned char**)&http_conf.request6,
            http_conf.req6_len,
            (const unsigned char *)http_conf.payload,
            http_conf.payload_length,
            http_req_payload);

        http_conf.req6_len = http_change_field(
            (unsigned char**)&http_conf.request6,
            http_conf.req6_len,
            "Content-Length:",
            (const unsigned char *)lenstr,
            strlen(lenstr),
            http_field_replace);
    }

    if (http_conf.user_agent) {
        http_conf.req4_len = http_change_field(
            (unsigned char**)&http_conf.request4,
            http_conf.req4_len,
            "User-Agent:",
            (const unsigned char *)http_conf.user_agent,
            http_conf.user_agent_length,
            http_field_replace);

        http_conf.req6_len = http_change_field(
            (unsigned char**)&http_conf.request6,
            http_conf.req6_len,
            "User-Agent:",
            (const unsigned char *)http_conf.user_agent,
            http_conf.user_agent_length,
            http_field_replace);
    }

    /*priority on dynamic host*/
    if (http_conf.host && !http_conf.dynamic_host) {
        http_conf.req4_len = http_change_field(
            (unsigned char**)&http_conf.request4,
            http_conf.req4_len,
            "Host:",
            (const unsigned char *)http_conf.host,
            http_conf.host_length,
            http_field_replace);

        http_conf.req6_len = http_change_field(
            (unsigned char**)&http_conf.request6,
            http_conf.req6_len,
            "Host:",
            (const unsigned char *)http_conf.host,
            http_conf.host_length,
            http_field_replace);
    }

    if (http_conf.dynamic_host) {
        http_conf.req4_len = http_change_field(
            (unsigned char**)&http_conf.request4,
            http_conf.req4_len,
            "Host:",
            (const unsigned char *)host_fmt_ipv4,
            sizeof(host_fmt_ipv4)-1,
            http_field_replace);

        http_conf.req6_len = http_change_field(
            (unsigned char**)&http_conf.request6,
            http_conf.req6_len,
            "Host:",
            (const unsigned char *)host_fmt_ipv6,
            sizeof(host_fmt_ipv6)-1,
            http_field_replace);
    }

    if (http_conf.method) {
        http_conf.req4_len = http_change_requestline(
            (unsigned char**)&http_conf.request4,
            http_conf.req4_len,
            (const unsigned char *)http_conf.method,
            http_conf.method_length,
            http_req_method);

        http_conf.req6_len = http_change_requestline(
            (unsigned char**)&http_conf.request6,
            http_conf.req6_len,
            (const unsigned char *)http_conf.method,
            http_conf.method_length,
            http_req_method);
    }

    if (http_conf.url) {
        http_conf.req4_len = http_change_requestline(
            (unsigned char**)&http_conf.request4,
            http_conf.req4_len,
            (const unsigned char *)http_conf.url,
            http_conf.url_length,
            http_req_url);

        http_conf.req6_len = http_change_requestline(
            (unsigned char**)&http_conf.request6,
            http_conf.req6_len,
            (const unsigned char *)http_conf.url,
            http_conf.url_length,
            http_req_url);
    }

    if (http_conf.version) {
        http_conf.req4_len = http_change_requestline(
            (unsigned char**)&http_conf.request4,
            http_conf.req4_len,
            (const unsigned char *)http_conf.version,
            http_conf.version_length,
            http_req_version);

        http_conf.req6_len = http_change_requestline(
            (unsigned char**)&http_conf.request6,
            http_conf.req6_len,
            (const unsigned char *)http_conf.version,
            http_conf.version_length,
            http_req_version);
    }

    for (size_t i=0; i<http_conf.headers_count; i++) {
        http_conf.req4_len = http_change_field(
            (unsigned char**)&http_conf.request4,
            http_conf.req4_len,
            http_conf.headers[i].name,
            (const unsigned char *)http_conf.headers[i].value,
            http_conf.headers[i].value_length,
            http_field_replace);

        http_conf.req6_len = http_change_field(
            (unsigned char**)&http_conf.request6,
            http_conf.req6_len,
            http_conf.headers[i].name,
            (const unsigned char *)http_conf.headers[i].value,
            http_conf.headers[i].value_length,
            http_field_replace);
    }

    for (size_t i=0; i<http_conf.cookies_count; i++) {
        http_conf.req4_len = http_change_field(
            (unsigned char**)&http_conf.request4,
            http_conf.req4_len,
            "Cookie",
            (const unsigned char *)http_conf.cookies[i].value,
            http_conf.cookies[i].value_length,
            http_field_add);

        http_conf.req6_len = http_change_field(
            (unsigned char**)&http_conf.request6,
            http_conf.req6_len,
            "Cookie",
            (const unsigned char *)http_conf.cookies[i].value,
            http_conf.cookies[i].value_length,
            http_field_add);
    }

    for (size_t i=0; i<http_conf.remove_count; i++) {
        http_conf.req4_len = http_change_field(
            (unsigned char**)&http_conf.request4,
            http_conf.req4_len,
            http_conf.remove[i].name,
            NULL,
            0,
            http_field_remove);

        http_conf.req6_len = http_change_field(
            (unsigned char**)&http_conf.request6,
            http_conf.req6_len,
            http_conf.remove[i].name,
            NULL,
            0,
            http_field_remove);
    }

    return true;
}

static size_t
http_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    if (http_conf.dynamic_host) {
        if (target->ip_them.version==4)
            return snprintf((char *)payload_buf,
                PROBE_PAYLOAD_MAX_LEN, http_conf.request4,
                ipaddress_fmt(target->ip_them).string);
        else
            return snprintf((char *)payload_buf,
                PROBE_PAYLOAD_MAX_LEN, http_conf.request6,
                ipaddress_fmt(target->ip_them).string);
    }

    memcpy(payload_buf, http_conf.request4, http_conf.req4_len);
    return http_conf.req4_len;
}

static size_t
http_get_payload_length(struct ProbeTarget *target)
{
    if (http_conf.dynamic_host) {
        unsigned char tmp_str[PROBE_PAYLOAD_MAX_LEN];
        return http_make_payload(target, tmp_str);
    }
    return http_conf.req4_len;
}

static unsigned
http_handle_response(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{

#ifndef NOT_FOUND_PCRE2

    if (http_conf.compiled_re) {
        pcre2_match_data *match_data;
        int rc;

        match_data = pcre2_match_data_create_from_pattern(http_conf.compiled_re, NULL);
        if (!match_data) {
            LOG(LEVEL_ERROR, "FAIL: cannot allocate match_data when matching.\n");
            item->no_output = 1;
            return 0;
        }

        rc = pcre2_match(http_conf.compiled_re,
            (PCRE2_SPTR8)px, (int)sizeof_px,
            0, 0, match_data, http_conf.match_ctx);

        /*matched one. ps: "offset is too small" means successful, too*/
        if (rc >= 0) {
            item->level = Output_SUCCESS;
            safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "success");
            safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "matched");
        } else {
            item->level = Output_FAILURE;
            safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "fail");
            safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "not matched");
        }
        
        if (http_conf.report_while_regex) {
            normalize_string(px, sizeof_px, item->report, OUTPUT_RPT_SIZE);
        }
        pcre2_match_data_free(match_data);
    } else {

#endif

        item->level = Output_SUCCESS;
        safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "serving");
        safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "banner exists");
        normalize_string(px, sizeof_px, item->report, OUTPUT_RPT_SIZE);

#ifndef NOT_FOUND_PCRE2
    }
#endif

    return 0;
}

static unsigned
http_handle_timeout(struct ProbeTarget *target, struct OutputItem *item)
{
    safe_strcpy(item->classification, OUTPUT_CLS_SIZE, "no service");
    safe_strcpy(item->reason, OUTPUT_RSN_SIZE, "timeout");
    item->level = Output_FAILURE;
    return 0;
}

static void
http_close()
{

#ifndef NOT_FOUND_PCRE2
    if (http_conf.regex) {
        free(http_conf.regex);
        http_conf.regex = NULL;
    }
    http_conf.regex_len = 0;

    if (http_conf.compiled_re) {
        pcre2_code_free(http_conf.compiled_re);
        http_conf.compiled_re = NULL;
    }

    if (http_conf.match_ctx) {
        pcre2_match_context_free(http_conf.match_ctx);
        http_conf.match_ctx = NULL;
    }
#endif

}

struct ProbeModule HttpProbe = {
    .name       = "http",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = http_parameters,
    .desc =
        "HttpProbe sends target port a user-defined HTTP request and save the "
        "response. Default HTTP request is based on:\n\n"
        "      `GET / HTTP/1.0`\n"
        "      `User-Agent: "XTATE_WITH_VERSION" "XTATE_GITHUB"`\n"
        "      `Accept: */*`\n\n"
        "We can use various args to change the default request and set a regex "
        "to match the response as successed.",
    .global_init_cb                    = &http_global_init,
    .make_payload_cb                   = &http_make_payload,
    .get_payload_length_cb             = &http_get_payload_length,
    .handle_response_cb                = &http_handle_response,
    .handle_timeout_cb                 = &http_handle_timeout,
    .close_cb                          = &http_close,
};
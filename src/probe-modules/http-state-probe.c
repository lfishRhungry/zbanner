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

static const char default_http_header[] =
    "GET / HTTP/1.0\r\n"
    "User-Agent: " XTATE_WITH_VERSION " " XTATE_GITHUB_URL "\r\n"
    "Accept: */*\r\n"
    "\r\n";

static const char host_fmt_ipv4[] = "%s";

static const char host_fmt_ipv6[] = "[%s]";

struct HttpStateConf {
    /*IPv4*/
    char  *request4;
    size_t req4_len;

    /*IPv6*/
    char  *request6;
    size_t req6_len;

    /* Method */
    char  *method;
    size_t method_length;

    /* URL */
    char  *url;
    size_t url_length;

    /* Version */
    char  *version;
    size_t version_length;

    /* Host */
    char  *host;
    size_t host_length;

    /* User-Agent */
    char  *user_agent;
    size_t user_agent_length;

    /* Payload after the header*/
    char  *payload;
    size_t payload_length;

    /* Headers */
    struct {
        const char *name;
        char       *value;
        size_t      value_length;
    } headers[16];
    size_t headers_count;

    /* Cookies */
    struct {
        char  *value;
        size_t value_length;
    } cookies[16];
    size_t cookies_count;

    /* Remove */
    struct {
        char *name;
    } remove[16];
    size_t remove_count;

#ifndef NOT_FOUND_PCRE2
    char                *regex;
    size_t               regex_len;
    pcre2_code          *compiled_re;
    pcre2_match_context *match_ctx;
    unsigned             re_case_insensitive  : 1;
    unsigned             re_include_newlines  : 1;
    unsigned             match_whole_response : 1;
#endif
    unsigned record_banner   : 1;
    unsigned record_utf8     : 1;
    unsigned record_data     : 1;
    unsigned record_data_len : 1;
    /*dynamic set ip:port as Host field*/
    unsigned dynamic_host    : 1;
    unsigned all_banner      : 1;
    unsigned all_banner_limit;
    unsigned all_banner_floor;
};

static struct HttpStateConf httpstate_conf = {0};

static ConfRes SET_all_banner_floor(void *conf, const char *name,
                                    const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    httpstate_conf.all_banner_floor = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_all_banner_limit(void *conf, const char *name,
                                    const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    httpstate_conf.all_banner_limit = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_all_banner(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    httpstate_conf.all_banner = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_data_len(void *conf, const char *name,
                                   const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    httpstate_conf.record_data_len = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_data(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    httpstate_conf.record_data = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_utf8(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    httpstate_conf.record_utf8 = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_banner(void *conf, const char *name,
                                 const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    httpstate_conf.record_banner = conf_parse_bool(value);

    return Conf_OK;
}

#ifndef NOT_FOUND_PCRE2

static ConfRes SET_match_whole_response(void *conf, const char *name,
                                        const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    httpstate_conf.match_whole_response = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_newlines(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    httpstate_conf.re_include_newlines = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_insensitive(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    httpstate_conf.re_case_insensitive = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_regex(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (httpstate_conf.compiled_re)
        pcre2_code_free(httpstate_conf.compiled_re);
    if (httpstate_conf.match_ctx)
        pcre2_match_context_free(httpstate_conf.match_ctx);

    httpstate_conf.regex_len = strlen(value);
    if (httpstate_conf.regex_len == 0) {
        LOG(LEVEL_ERROR, "Invalid regex.\n");
        return Conf_ERR;
    }

    int        pcre2_errcode;
    PCRE2_SIZE pcre2_erroffset;
    httpstate_conf.regex       = STRDUP(value);
    httpstate_conf.compiled_re = pcre2_compile(
        (PCRE2_SPTR)httpstate_conf.regex, PCRE2_ZERO_TERMINATED,
        (httpstate_conf.re_case_insensitive ? PCRE2_CASELESS : 0) |
            (httpstate_conf.re_include_newlines ? PCRE2_DOTALL : 0),
        &pcre2_errcode, &pcre2_erroffset, NULL);

    if (!httpstate_conf.compiled_re) {
        LOG(LEVEL_ERROR, "Regex compiled failed.\n");
        return Conf_ERR;
    }

    httpstate_conf.match_ctx = pcre2_match_context_create(NULL);
    if (!httpstate_conf.match_ctx) {
        LOG(LEVEL_ERROR, "Regex allocates match_ctx failed.\n");
        return Conf_ERR;
    }

    pcre2_set_match_limit(httpstate_conf.match_ctx, 100000);

#ifdef pcre2_set_depth_limit
    // Changed name in PCRE2 10.30. PCRE2 uses macro definitions for function
    // names, so we don't have to add this to configure.ac.
    pcre2_set_depth_limit(httpstate_conf.match_ctx, 10000);
#else
    pcre2_set_recursion_limit(httpstate_conf.match_ctx, 10000);
#endif

    return Conf_OK;
}

#endif

static ConfRes SET_method(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(httpstate_conf.method);

    httpstate_conf.method_length = strlen(value);
    httpstate_conf.method        = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_url(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(httpstate_conf.url);

    httpstate_conf.url_length = strlen(value);
    httpstate_conf.url        = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_version(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(httpstate_conf.version);

    httpstate_conf.version_length = strlen(value);
    httpstate_conf.version        = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_host(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(httpstate_conf.host);

    httpstate_conf.host_length = strlen(value);
    httpstate_conf.host        = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_user_agent(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(httpstate_conf.user_agent);

    httpstate_conf.user_agent_length = strlen(value);
    httpstate_conf.user_agent        = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_payload(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(httpstate_conf.payload);

    httpstate_conf.payload_length = strlen(value);
    httpstate_conf.payload        = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_header(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);

    char    *newname;
    char    *newvalue;
    unsigned name_length;
    size_t   value_length;
    /*
     * allocate a new name
     */
    name += 6;
    if (*name == '[') {
        /* Specified as: "--header[name] value" */
        while (ispunct(*name))
            name++;
        name_length = (unsigned)strlen(name);
        while (name_length && ispunct(name[name_length - 1]))
            name_length--;
        newname = MALLOC(name_length + 1);
        memcpy(newname, name, name_length + 1);
        newname[name_length] = '\0';
    } else if (strchr(value, ':')) {
        /* Specified as: "--header Name:value" */
        name_length = conf_index_of(value, ':');
        newname     = MALLOC(name_length + 1);
        memcpy(newname, value, name_length + 1);

        /* Trim the value */
        value = value + name_length + 1;
        while (*value && isspace(*value & 0xFF))
            value++;

        /* Trim the name */
        while (name_length && isspace(newname[name_length - 1] & 0xFF))
            name_length--;
        newname[name_length] = '\0';
    } else {
        LOG(LEVEL_ERROR, "--header needs both a name and value\n");
        LOG(LEVEL_HINT, "    \"--header Name:value\"\n");
        return Conf_ERR;
    }

    /* allocate new value */
    value_length = strlen(value);
    newvalue     = MALLOC(value_length + 1);
    memcpy(newvalue, value, value_length + 1);
    newvalue[value_length] = '\0';

    /* Add to our list of headers */
    if (httpstate_conf.headers_count < ARRAY_SIZE(httpstate_conf.headers)) {
        size_t x                               = httpstate_conf.headers_count;
        httpstate_conf.headers[x].name         = newname;
        httpstate_conf.headers[x].value        = newvalue;
        httpstate_conf.headers[x].value_length = value_length;
        httpstate_conf.headers_count++;
    }

    return Conf_OK;
}

static ConfRes SET_cookie(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    char  *newvalue;
    size_t value_length;

    /* allocate new value */
    value_length = strlen(value);
    newvalue     = MALLOC(value_length + 1);
    memcpy(newvalue, value, value_length + 1);
    newvalue[value_length] = '\0';

    /* Add to our list of headers */
    if (httpstate_conf.cookies_count < ARRAY_SIZE(httpstate_conf.cookies)) {
        size_t x                               = httpstate_conf.cookies_count;
        httpstate_conf.cookies[x].value        = newvalue;
        httpstate_conf.cookies[x].value_length = value_length;
        httpstate_conf.cookies_count++;
    }

    return Conf_OK;
}

static ConfRes SET_remove(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    char  *newvalue;
    size_t value_length;

    /* allocate new value */
    value_length = strlen(value);
    newvalue     = MALLOC(value_length + 1);
    memcpy(newvalue, value, value_length + 1);
    newvalue[value_length] = '\0';

    /* Add to our list of headers */
    if (httpstate_conf.remove_count < ARRAY_SIZE(httpstate_conf.remove)) {
        size_t x                      = httpstate_conf.remove_count;
        httpstate_conf.remove[x].name = newvalue;
        httpstate_conf.remove_count++;
    }

    return Conf_OK;
}

static ConfRes SET_dynamic_host(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    httpstate_conf.dynamic_host = conf_parse_bool(value);

    return Conf_OK;
}

static ConfParam httpstate_parameters[] = {
    {"method",
     SET_method,
     Type_ARG,
     {0},
     "Changes the default `GET` method in http request line."},
    {"url",
     SET_url,
     Type_ARG,
     {0},
     "Replaces the existing `/` url field in http request line."},
    {"version",
     SET_version,
     Type_ARG,
     {"ver", 0},
     "Replaces the existing `HTTP/1.0` version field in http request line."},
    {"host",
     SET_host,
     Type_ARG,
     {0},
     "Adds `Host` field to http request header."},
    {"dynamic-host",
     SET_dynamic_host,
     Type_FLAG,
     {"ip-host", 0},
     "Sets(Adds) correspond IP address as `Host` field to http request header"
     " for different target e.g. `Host: 192.168.0.1`, `Host: [fe80::1]`."},
    {"user-agent",
     SET_user_agent,
     Type_ARG,
     {"ua", 0},
     "Replaces existing `User-Agent` field in http request header.(highly "
     "recommended)"},
    {"payload",
     SET_payload,
     Type_ARG,
     {0},
     "Adds a payload string after http request header. This will automatically"
     " add `--header Content-Length:LEN` field to match the length of the "
     "string.\n"
     "NOTE: We should add our own `--header Content-Type:TYPE` field to match"
     " the string. Presumably, we will also change the method to something "
     "like `--method POST`. Common `Content-Type` would be `application/x-www-"
     "form-urlencoded`, `application/json`, or `text/xml`."},
    {"cookie",
     SET_cookie,
     Type_ARG,
     {0},
     "Adds a `Cookie` field to http request header even if other cookie fields"
     " exist."},
    {"header",
     SET_header,
     Type_ARG,
     {0},
     "Replaces the existing http request header field or inserts a new one if"
     " the fields doesn't exist, given as a `name:value` pair. It cannot be "
     "used to replace the fields in the request line e.g. method, url and "
     "version.\n"
     "Example: `--header Accept:image/gif`, `--header[Accept] image/gif`\n"},
    {"remove",
     SET_remove,
     Type_ARG,
     {0},
     "Removes the first field from the header that matches. We may need "
     "multiple times for fields like `Cookie` that can exist multiple times."},
    {"all-banner",
     SET_all_banner,
     Type_FLAG,
     {"banner-all", 0},
     "Get the whole responsed banner before connection timeout, not just the "
     "banner in the first segment."},
    {"all-banner-limit",
     SET_all_banner_limit,
     Type_ARG,
     {"banner-limit", "limit-banner", 0},
     "Just record limited number of ACK segments with banner data as results "
     "in all-banner mode. Exceeded ACK segments with banner data won't trigger "
     "Multi_DynamicNext or Multi_AfterHandle."},
    {"banner-floor",
     SET_all_banner_floor,
     Type_ARG,
     {"banner-floor", "floor-banner", 0},
     "Do not record ACK segments with banner data as results if the number is "
     "less than the floor value while in all-banner mode. And non-recorded "
     "segments won't trigger Multi_DynamicNext or Multi_AfterHandle."},

#ifndef NOT_FOUND_PCRE2
    {"regex",
     SET_regex,
     Type_ARG,
     {0},
     "Specifies a regex and sets matched response data as successed instead of"
     " reporting all results."},
    {"case-insensitive",
     SET_insensitive,
     Type_FLAG,
     {"insensitive", 0},
     "Whether the specified regex is case-insensitive or not."},
    {"include-newlines",
     SET_newlines,
     Type_FLAG,
     {"include-newline", "newline", "newlines", 0},
     "Whether the specified regex contains newlines."},
    {"match-whole-response",
     SET_match_whole_response,
     Type_FLAG,
     {"match-whole", "whole-match", 0},
     "Continue to match the whole response after matched previous content "
     "instead of trying to close the connection.\n"
     "NOTE: it works while using -all-banner."},
#endif

    {"record-banner",
     SET_record_banner,
     Type_FLAG,
     {"banner", 0},
     "Records banner content in escaped text style."},
    {"record-utf8",
     SET_record_utf8,
     Type_FLAG,
     {"utf8", 0},
     "Records banner content with escaped valid utf8 encoding."},
    {"record-data",
     SET_record_data,
     Type_FLAG,
     {"data", 0},
     "Records data content in binary format."},
    {"record-data-len",
     SET_record_data_len,
     Type_FLAG,
     {"data-len", "len", 0},
     "Records payload data length."},

    {0}};

/*for internal x-ref*/
extern Probe HttpStateProbe;

static bool http_init(const XConf *xconf) {
    httpstate_conf.req4_len = sizeof(default_http_header);
    httpstate_conf.request4 = MALLOC(httpstate_conf.req4_len);
    memcpy(httpstate_conf.request4, default_http_header,
           httpstate_conf.req4_len);

    httpstate_conf.req6_len = sizeof(default_http_header);
    httpstate_conf.request6 = MALLOC(httpstate_conf.req6_len);
    memcpy(httpstate_conf.request6, default_http_header,
           httpstate_conf.req6_len);

    if (httpstate_conf.payload) {
        char lenstr[64];
        snprintf(lenstr, sizeof(lenstr), "%u",
                 (unsigned)httpstate_conf.payload_length);

        httpstate_conf.req4_len = http_change_requestline(
            (unsigned char **)&httpstate_conf.request4, httpstate_conf.req4_len,
            (const unsigned char *)httpstate_conf.payload,
            httpstate_conf.payload_length, http_req_payload);

        httpstate_conf.req4_len = http_change_field(
            (unsigned char **)&httpstate_conf.request4, httpstate_conf.req4_len,
            "Content-Length:", (const unsigned char *)lenstr, strlen(lenstr),
            http_field_replace);

        httpstate_conf.req6_len = http_change_requestline(
            (unsigned char **)&httpstate_conf.request6, httpstate_conf.req6_len,
            (const unsigned char *)httpstate_conf.payload,
            httpstate_conf.payload_length, http_req_payload);

        httpstate_conf.req6_len = http_change_field(
            (unsigned char **)&httpstate_conf.request6, httpstate_conf.req6_len,
            "Content-Length:", (const unsigned char *)lenstr, strlen(lenstr),
            http_field_replace);
    }

    if (httpstate_conf.user_agent) {
        httpstate_conf.req4_len = http_change_field(
            (unsigned char **)&httpstate_conf.request4, httpstate_conf.req4_len,
            "User-Agent:", (const unsigned char *)httpstate_conf.user_agent,
            httpstate_conf.user_agent_length, http_field_replace);

        httpstate_conf.req6_len = http_change_field(
            (unsigned char **)&httpstate_conf.request6, httpstate_conf.req6_len,
            "User-Agent:", (const unsigned char *)httpstate_conf.user_agent,
            httpstate_conf.user_agent_length, http_field_replace);
    }

    /*priority on dynamic host*/
    if (httpstate_conf.host && !httpstate_conf.dynamic_host) {
        httpstate_conf.req4_len = http_change_field(
            (unsigned char **)&httpstate_conf.request4, httpstate_conf.req4_len,
            "Host:", (const unsigned char *)httpstate_conf.host,
            httpstate_conf.host_length, http_field_replace);

        httpstate_conf.req6_len = http_change_field(
            (unsigned char **)&httpstate_conf.request6, httpstate_conf.req6_len,
            "Host:", (const unsigned char *)httpstate_conf.host,
            httpstate_conf.host_length, http_field_replace);
    }

    if (httpstate_conf.dynamic_host) {
        httpstate_conf.req4_len = http_change_field(
            (unsigned char **)&httpstate_conf.request4, httpstate_conf.req4_len,
            "Host:", (const unsigned char *)host_fmt_ipv4,
            sizeof(host_fmt_ipv4) - 1, http_field_replace);

        httpstate_conf.req6_len = http_change_field(
            (unsigned char **)&httpstate_conf.request6, httpstate_conf.req6_len,
            "Host:", (const unsigned char *)host_fmt_ipv6,
            sizeof(host_fmt_ipv6) - 1, http_field_replace);
    }

    if (httpstate_conf.method) {
        httpstate_conf.req4_len = http_change_requestline(
            (unsigned char **)&httpstate_conf.request4, httpstate_conf.req4_len,
            (const unsigned char *)httpstate_conf.method,
            httpstate_conf.method_length, http_req_method);

        httpstate_conf.req6_len = http_change_requestline(
            (unsigned char **)&httpstate_conf.request6, httpstate_conf.req6_len,
            (const unsigned char *)httpstate_conf.method,
            httpstate_conf.method_length, http_req_method);
    }

    if (httpstate_conf.url) {
        httpstate_conf.req4_len = http_change_requestline(
            (unsigned char **)&httpstate_conf.request4, httpstate_conf.req4_len,
            (const unsigned char *)httpstate_conf.url,
            httpstate_conf.url_length, http_req_url);

        httpstate_conf.req6_len = http_change_requestline(
            (unsigned char **)&httpstate_conf.request6, httpstate_conf.req6_len,
            (const unsigned char *)httpstate_conf.url,
            httpstate_conf.url_length, http_req_url);
    }

    if (httpstate_conf.version) {
        httpstate_conf.req4_len = http_change_requestline(
            (unsigned char **)&httpstate_conf.request4, httpstate_conf.req4_len,
            (const unsigned char *)httpstate_conf.version,
            httpstate_conf.version_length, http_req_version);

        httpstate_conf.req6_len = http_change_requestline(
            (unsigned char **)&httpstate_conf.request6, httpstate_conf.req6_len,
            (const unsigned char *)httpstate_conf.version,
            httpstate_conf.version_length, http_req_version);
    }

    for (size_t i = 0; i < httpstate_conf.headers_count; i++) {
        httpstate_conf.req4_len = http_change_field(
            (unsigned char **)&httpstate_conf.request4, httpstate_conf.req4_len,
            httpstate_conf.headers[i].name,
            (const unsigned char *)httpstate_conf.headers[i].value,
            httpstate_conf.headers[i].value_length, http_field_replace);

        httpstate_conf.req6_len = http_change_field(
            (unsigned char **)&httpstate_conf.request6, httpstate_conf.req6_len,
            httpstate_conf.headers[i].name,
            (const unsigned char *)httpstate_conf.headers[i].value,
            httpstate_conf.headers[i].value_length, http_field_replace);
    }

    for (size_t i = 0; i < httpstate_conf.cookies_count; i++) {
        httpstate_conf.req4_len = http_change_field(
            (unsigned char **)&httpstate_conf.request4, httpstate_conf.req4_len,
            "Cookie", (const unsigned char *)httpstate_conf.cookies[i].value,
            httpstate_conf.cookies[i].value_length, http_field_add);

        httpstate_conf.req6_len = http_change_field(
            (unsigned char **)&httpstate_conf.request6, httpstate_conf.req6_len,
            "Cookie", (const unsigned char *)httpstate_conf.cookies[i].value,
            httpstate_conf.cookies[i].value_length, http_field_add);
    }

    for (size_t i = 0; i < httpstate_conf.remove_count; i++) {
        httpstate_conf.req4_len = http_change_field(
            (unsigned char **)&httpstate_conf.request4, httpstate_conf.req4_len,
            httpstate_conf.remove[i].name, NULL, 0, http_field_remove);

        httpstate_conf.req6_len = http_change_field(
            (unsigned char **)&httpstate_conf.request6, httpstate_conf.req6_len,
            httpstate_conf.remove[i].name, NULL, 0, http_field_remove);
    }

    return true;
}

static void httpstate_make_hello(DataPass *pass, ProbeState *state,
                                 ProbeTarget *target) {
    if (httpstate_conf.dynamic_host) {
        if (target->target.ip_them.version == 4) {
            pass->data = MALLOC(httpstate_conf.req4_len + 20);
            pass->len =
                snprintf((char *)pass->data, httpstate_conf.req4_len + 20,
                         httpstate_conf.request4,
                         ipaddress_fmt(target->target.ip_them).string);
        } else {
            pass->data = MALLOC(httpstate_conf.req6_len + 50);
            pass->len =
                snprintf((char *)pass->data, httpstate_conf.req6_len + 50,
                         httpstate_conf.request6,
                         ipaddress_fmt(target->target.ip_them).string);
        }

        pass->is_dynamic = 1;
    } else {
        datapass_set_data(pass, (unsigned char *)httpstate_conf.request4,
                          httpstate_conf.req4_len, false);
    }
}

static unsigned httpstate_parse_response(DataPass *pass, ProbeState *state,
                                         OutConf *out, ProbeTarget *target,
                                         const unsigned char *px,
                                         unsigned             sizeof_px) {
    state->state++;

    if (!httpstate_conf.all_banner) {
        pass->is_close = 1;

        if (state->state > 1)
            return 0;
    }

    if (httpstate_conf.all_banner && httpstate_conf.all_banner_limit &&
        state->state >= httpstate_conf.all_banner_limit) {
        pass->is_close = 1;

        if (state->state > httpstate_conf.all_banner_limit)
            return 0;
        if (state->state < httpstate_conf.all_banner_floor)
            return 0;
    }

    if (httpstate_conf.all_banner && httpstate_conf.all_banner_floor &&
        state->state < httpstate_conf.all_banner_floor) {
        return 0;
    }

    OutItem item = {
        .target.ip_proto  = target->target.ip_proto,
        .target.ip_them   = target->target.ip_them,
        .target.ip_me     = target->target.ip_me,
        .target.port_them = target->target.port_them,
        .target.port_me   = target->target.port_me,
    };

#ifndef NOT_FOUND_PCRE2

    if (httpstate_conf.compiled_re) {
        pcre2_match_data *match_data;
        int               rc;

        match_data = pcre2_match_data_create_from_pattern(
            httpstate_conf.compiled_re, NULL);
        if (!match_data) {
            LOG(LEVEL_ERROR, "cannot allocate match_data when matching.\n");
            item.no_output = 1;
            return 0;
        }

        rc = pcre2_match(httpstate_conf.compiled_re, (PCRE2_SPTR8)px,
                         (int)sizeof_px, 0, 0, match_data,
                         httpstate_conf.match_ctx);

        /*matched one. ps: "offset is too small" means successful, too*/
        if (rc >= 0) {
            item.level = OUT_SUCCESS;
            safe_strcpy(item.classification, OUT_CLS_SIZE, "matched");

            if (!httpstate_conf.match_whole_response) {
                pass->is_close = 1;
            }
        } else {
            item.level = OUT_FAILURE;
            safe_strcpy(item.classification, OUT_CLS_SIZE, "not matched");
        }

        pcre2_match_data_free(match_data);
    } else {
#endif

        item.level = OUT_SUCCESS;

#ifndef NOT_FOUND_PCRE2
    }
#endif

    if (httpstate_conf.all_banner) {
        dach_set_int(&item.probe_report, "banner idx", state->state - 1);
    }
    if (httpstate_conf.record_data_len) {
        dach_set_int(&item.probe_report, "data len", sizeof_px);
    }
    if (httpstate_conf.record_data)
        dach_append_bin(&item.probe_report, "data", px, sizeof_px);
    if (httpstate_conf.record_utf8)
        dach_append_utf8(&item.probe_report, "utf8", px, sizeof_px);
    if (httpstate_conf.record_banner)
        dach_append_banner(&item.probe_report, "banner", px, sizeof_px);

    output_result(out, &item);

    return 0;
}

static void httpstate_close() {
#ifndef NOT_FOUND_PCRE2
    FREE(httpstate_conf.regex);
    httpstate_conf.regex_len = 0;

    if (httpstate_conf.compiled_re) {
        pcre2_code_free(httpstate_conf.compiled_re);
        httpstate_conf.compiled_re = NULL;
    }

    if (httpstate_conf.match_ctx) {
        pcre2_match_context_free(httpstate_conf.match_ctx);
        httpstate_conf.match_ctx = NULL;
    }
#endif
}

Probe HttpStateProbe = {
    .name       = "http-state",
    .type       = ProbeType_STATE,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .hello_wait = 0,
    .params     = httpstate_parameters,
    .short_desc = "Send user-specified HTTP request and get response in "
                  "stateful TCP scan.",
    .desc =
        "HttpStateProbe is the stateful version of HttpProbe, it sends target "
        "port a user-defined HTTP request and save the response. Default HTTP "
        "request is based on:\n\n"
        "      `GET / HTTP/1.0`\n"
        "      `User-Agent: " XTATE_WITH_VERSION " " XTATE_GITHUB_URL "`\n"
        "      `Accept: */*`\n\n"
        "We can use various args to change the default request and set a regex "
        "to match the response as successed.\n"
        "NOTE: HttpStateProbe could be used over TLS.\n"
        "Dependencies: PCRE2 for regex.",

    .init_cb           = &http_init,
    .conn_init_cb      = &probe_conn_init_nothing,
    .make_hello_cb     = &httpstate_make_hello,
    .parse_response_cb = &httpstate_parse_response,
    .conn_close_cb     = &probe_conn_close_nothing,
    .close_cb          = &httpstate_close,
};
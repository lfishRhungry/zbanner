#include "output-modules.h"

#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../pixie/pixie-file.h"

extern Output NdjsonOutput; /*for internal x-ref*/

static FILE *file;

static const char header_json[]        = "[";
static const char tail_json[]          = "\n]\n";
static const char fmt_json_prefix[]    = ",\n    {\n"
                                         "        \"time\": \"%s\",\n"
                                         "        \"level\": \"%s\",\n"
                                         "        \"ip_proto\": \"%s\",\n"
                                         "        \"ip_them\": \"%s\",\n";
static const char fmt_json_port_them[] = "        \"port_them\": %u,\n";
static const char fmt_json_ip_me[]     = "        \"ip_me\": \"%s\",\n";
static const char fmt_json_port_me[]   = "        \"port_me\": %u,\n";
static const char fmt_json_inffix[]    = "        \"classification\": \"%s\",\n"
                                         "        \"reason\": \"%s\",\n"
                                         "        \"report\": {";
static const char fmt_json_str_inffix[] = ",\n            \"%s\": \"%s\"";
static const char fmt_json_bin_inffix[] =
    ",\n            \"%s\": \"(%u bytes bin)\"";
static const char fmt_json_int_inffix[]    = ",\n            \"%s\": %" PRIu64;
static const char fmt_json_double_inffix[] = ",\n            \"%s\": %.2f";
static const char fmt_json_true_inffix[]   = ",\n            \"%s\": true";
static const char fmt_json_false_inffix[]  = ",\n            \"%s\": false";
static const char fmt_json_suffix1[]       = "\n        }\n" /*close report*/
                                       "    }";              /*cose all*/
static const char fmt_json_suffix2[] = " }\n"                /*close report*/
                                       "    }";              /*cose all*/

static char     format_time[32];
static unsigned is_first_result = 1;

static bool json_init(const XConf *xconf, const OutConf *out) {
    /*a convention*/
    if (out->output_filename[0] == '-' && strlen(out->output_filename) == 1) {
        file = stdout;
        return true;
    }

    int err =
        pixie_fopen_shareable(&file, out->output_filename, out->is_append);

    if (err != 0 || file == NULL) {
        LOG(LEVEL_ERROR, "(JsonOutput) could not open file %s for %s.\n",
            out->output_filename, out->is_append ? "appending" : "writing");
        LOGPERROR(out->output_filename);
        return false;
    }

    err = fputs(header_json, file);

    if (err < 0) {
        LOG(LEVEL_ERROR, "(JsonOutput) could not write header to file.\n");
    }

    return true;
}

static void json_result(OutItem *item) {
    int err;

    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->target.ip_them);
    ipaddress_formatted_t ip_me_fmt   = ipaddress_fmt(item->target.ip_me);

    iso8601_time_str(format_time, sizeof(format_time), &item->timestamp);

    err =
        fprintf(file, fmt_json_prefix + is_first_result, format_time,
                output_level_to_string(item->level),
                ip_proto_to_string(item->target.ip_proto), ip_them_fmt.string);
    is_first_result = 0;

    if (err < 0)
        goto error;

    if (!item->no_port) {
        err = fprintf(file, fmt_json_port_them, item->target.port_them);
        if (err < 0)
            goto error;
    }

    err = fprintf(file, fmt_json_ip_me, ip_me_fmt.string);
    if (err < 0)
        goto error;

    if (!item->no_port) {
        err = fprintf(file, fmt_json_port_me, item->target.port_me);
        if (err < 0)
            goto error;
    }

    err = fprintf(file, fmt_json_inffix, item->classification, item->reason);
    if (err < 0)
        goto error;

    DataLink *pre      = &item->report.link;
    unsigned  is_first = 1; /*no comma for first item*/
    while (pre->next) {
        if (pre->next->link_type == LinkType_String) {
            err = fprintf(file, fmt_json_str_inffix + is_first, pre->next->name,
                          pre->next->value_data);
        } else if (pre->next->link_type == LinkType_Int) {
            err = fprintf(file, fmt_json_int_inffix + is_first, pre->next->name,
                          pre->next->value_int);
        } else if (pre->next->link_type == LinkType_Double) {
            err = fprintf(file, fmt_json_double_inffix + is_first,
                          pre->next->name, pre->next->value_double);
        } else if (pre->next->link_type == LinkType_Bool) {
            err = fprintf(file,
                          pre->next->value_bool
                              ? fmt_json_true_inffix + is_first
                              : fmt_json_false_inffix + is_first,
                          pre->next->name);
        } else if (pre->next->link_type == LinkType_Binary) {
            err = fprintf(file, fmt_json_bin_inffix + is_first, pre->next->name,
                          pre->next->data_len);
        }

        if (err < 0)
            goto error;

        pre      = pre->next;
        is_first = 0;
    }

    /*at least one report, overwrite the last comma*/
    if (item->report.link.next) {
        err = fprintf(file, fmt_json_suffix1);
    } else {
        err = fprintf(file, fmt_json_suffix2);
    }

    if (err < 0)
        goto error;

    return;

error:
    LOG(LEVEL_ERROR, "(JsonOutput) could not write result to file.\n");
}

static void json_close(const OutConf *out) {

    int err = fputs(tail_json, file);

    if (err < 0) {
        LOG(LEVEL_WARN, "(JsonOutput) could not write tail to file.\n");
    }

    fflush(file);
    if (file != stdout) {
        fclose(file);
    }
}

Output JsonOutput = {
    .name       = "json",
    .need_file  = true,
    .params     = NULL,
    .short_desc = "Save results in pretty JSON format.",
    .desc =
        "JsonOutput save results in json format in pretty style to "
        "specified file.\n"
        "NOTE1: JsonOutput doesn't convert any escaped chars actively.\n"
        "NOTE2: Output results from some modules is not standard JSON string.\n"
        "NOTE3: JsonOutput would generate large file if the number of results "
        "is large. However, json in pretty style is just for human read-well.",

    .init_cb   = &json_init,
    .result_cb = &json_result,
    .close_cb  = &json_close,
};
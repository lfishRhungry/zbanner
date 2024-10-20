#include "output-modules.h"

#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../pixie/pixie-file.h"

extern Output NdjsonOutput; /*for internal x-ref*/

static FILE *file;

static const char fmt_ndjson_prefix[]        = "{"
                                               "\"time\":\"%s\","
                                               "\"level\":\"%s\","
                                               "\"ip_proto\":\"%s\","
                                               "\"ip_them\":\"%s\",";
static const char fmt_ndjson_port_them[]     = "\"port_them\":%u,";
static const char fmt_ndjson_ip_me[]         = "\"ip_me\":\"%s\",";
static const char fmt_ndjson_port_me[]       = "\"port_me\":%u,";
static const char fmt_ndjson_inffix[]        = "\"classification\":\"%s\","
                                               "\"reason\":\"%s\","
                                               "\"report\":{";
static const char fmt_ndjson_str_inffix[]    = ",\"%s\":\"%s\"";
static const char fmt_ndjson_bin_inffix[]    = ",\"%s\":\"(%u bytes bin)\"";
static const char fmt_ndjson_int_inffix[]    = ",\"%s\":%" PRIu64;
static const char fmt_ndjson_double_inffix[] = ",\"%s\":%.2f";
static const char fmt_ndjson_true_inffix[]   = ",\"%s\":true";
static const char fmt_ndjson_false_inffix[]  = ",\"%s\":false";
static const char fmt_ndjson_suffix[]        = "}" /*close report*/
                                        "}"        /*cose all*/
                                        "\n";

static char format_time[32];

static bool ndjson_init(const XConf *xconf, const OutConf *out) {
    /*a convention*/
    if (out->output_filename[0] == '-' && strlen(out->output_filename) == 1) {
        file = stdout;
        return true;
    }

    int err =
        pixie_fopen_shareable(&file, out->output_filename, out->is_append);

    if (err != 0 || file == NULL) {
        LOG(LEVEL_ERROR, "(NdjsonOutput) could not open file %s for %s.\n",
            out->output_filename, out->is_append ? "appending" : "writing");
        LOGPERROR(out->output_filename);
        return false;
    }

    return true;
}

static void ndjson_result(OutItem *item) {
    int err;

    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->target.ip_them);
    ipaddress_formatted_t ip_me_fmt   = ipaddress_fmt(item->target.ip_me);

    iso8601_time_str(format_time, sizeof(format_time), &item->timestamp);

    err =
        fprintf(file, fmt_ndjson_prefix, format_time,
                output_level_to_string(item->level),
                ip_proto_to_string(item->target.ip_proto), ip_them_fmt.string);

    if (err < 0)
        goto error;

    if (!item->no_port) {
        err = fprintf(file, fmt_ndjson_port_them, item->target.port_them);
        if (err < 0)
            goto error;
    }

    err = fprintf(file, fmt_ndjson_ip_me, ip_me_fmt.string);
    if (err < 0)
        goto error;

    if (!item->no_port) {
        err = fprintf(file, fmt_ndjson_port_me, item->target.port_me);
        if (err < 0)
            goto error;
    }

    err = fprintf(file, fmt_ndjson_inffix, item->classification, item->reason);
    if (err < 0)
        goto error;

    DataLink *pre      = item->report.link;
    unsigned  is_first = 1; /*no comma for first item*/
    while (pre->next) {
        if (pre->next->link_type == LinkType_String) {
            err = fprintf(file, fmt_ndjson_str_inffix + is_first,
                          pre->next->name, pre->next->value_data);
        } else if (pre->next->link_type == LinkType_Int) {
            err = fprintf(file, fmt_ndjson_int_inffix + is_first,
                          pre->next->name, pre->next->value_int);
        } else if (pre->next->link_type == LinkType_Double) {
            err = fprintf(file, fmt_ndjson_double_inffix + is_first,
                          pre->next->name, pre->next->value_double);
        } else if (pre->next->link_type == LinkType_Bool) {
            err = fprintf(file,
                          pre->next->value_bool
                              ? fmt_ndjson_true_inffix + is_first
                              : fmt_ndjson_false_inffix + is_first,
                          pre->next->name);
        } else if (pre->next->link_type == LinkType_Binary) {
            err = fprintf(file, fmt_ndjson_bin_inffix + is_first,
                          pre->next->name, pre->next->data_len);
        }

        if (err < 0)
            goto error;

        pre      = pre->next;
        is_first = 0;
    }

    err = fprintf(file, fmt_ndjson_suffix);
    if (err < 0)
        goto error;

    return;

error:
    LOG(LEVEL_ERROR, "(NdjsonOutput) could not write result to file.\n");
}

static void ndjson_close(const OutConf *out) {
    fflush(file);
    if (file != stdout) {
        fclose(file);
    }
}

Output NdjsonOutput = {
    .name       = "ndjson",
    .need_file  = true,
    .params     = NULL,
    .short_desc = "Save results in NDJSON format.",
    .desc =
        "NdjsonOutput save results in Newline-Delimited JSON(NDJSON) format to "
        "specified file. The format is also called JSONL(ines) and its filename"
        " suffix can be '.jsonl'.\n"
        "NOTE1: NdjsonOutput doesn't convert any escaped chars actively.\n"
        "NOTE2: Results from some modules is not standard string for JSON.",

    .init_cb   = &ndjson_init,
    .result_cb = &ndjson_result,
    .close_cb  = &ndjson_close,
};
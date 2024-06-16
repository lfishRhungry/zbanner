#include "output-modules.h"

#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../pixie/pixie-file.h"

extern struct OutputModule NdjsonOutput; /*for internal x-ref*/

static FILE *file;

static const char fmt_ndjson_prefix[] =
"{"
"\"time\":\"%s\","
"\"level\":\"%s\","
"\"ip_proto\":\"%s\","
"\"ip_them\":\"%s\","
;

static const char fmt_ndjson_port_them[] =
"\"port_them\":%u,"
;

static const char fmt_ndjson_ip_me[] =
"\"ip_me\":\"%s\","
;

static const char fmt_ndjson_port_me[] =
"\"port_me\":%u,"
;

static const char fmt_ndjson_inffix[] =
"\"classification\":\"%s\","
"\"reason\":\"%s\","
"\"report\":{"
;

static const char fmt_ndjson_str_inffix[] =
"\"%s\":\"%s\","
;

static const char fmt_ndjson_num_inffix[] =
"\"%s\":%s,"
;

static const char fmt_ndjson_suffix[] =
    "}"    /*close report*/
"}"        /*cose all*/
"\n"
;

static char format_time[32];

static bool
ndjson_init(const struct Output *out)
{

    int err = pixie_fopen_shareable(
        &file, out->output_filename, out->is_append);

    if (err != 0 || file == NULL) {
        LOG(LEVEL_ERROR, "NdjsonOutput: could not open file %s for %s.\n",
            out->output_filename, out->is_append?"appending":"writing");
        perror(out->output_filename);
        return false;
    }

    return true;
}

static void
ndjson_result(struct OutputItem *item)
{
    int err;

    bool output_port = (item->ip_proto==IP_PROTO_TCP
        || item->ip_proto==IP_PROTO_UDP || item->ip_proto==IP_PROTO_SCTP);

    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->ip_them);
    ipaddress_formatted_t ip_me_fmt   = ipaddress_fmt(item->ip_me);

    iso8601_time_str(format_time, sizeof(format_time), &item->timestamp);

    err = fprintf(file, fmt_ndjson_prefix,
        format_time,
        output_level_to_string(item->level),
        ip_proto_to_string(item->ip_proto),
        ip_them_fmt.string);

    if (err<0) goto error;

    if (output_port) {
        err = fprintf(file, fmt_ndjson_port_them, item->port_them);
        if (err<0) goto error;
    }

    err = fprintf(file, fmt_ndjson_ip_me, ip_me_fmt.string);
    if (err<0) goto error;

    if (output_port) {
        err = fprintf(file, fmt_ndjson_port_me, item->port_me);
        if (err<0) goto error;
    }

    err = fprintf(file, fmt_ndjson_inffix,
        item->classification,
        item->reason);
    if (err<0) goto error;

    struct DataLink *pre = item->report.link;
    while (pre->next) {
        err = fprintf(file,
            pre->next->is_number?fmt_ndjson_num_inffix:fmt_ndjson_str_inffix,
            pre->next->name, pre->next->data);
        if (err<0) goto error;
        pre = pre->next;
    }

    /*at least one report, overwrite the last comma*/
    if (item->report.link->next) {
        fseek(file, -1, SEEK_CUR);
    }

    err = fprintf(file, fmt_ndjson_suffix);
    if (err<0) goto error;

    return;

error:
    LOG(LEVEL_ERROR, "NdjsonOutput: could not write result to file.\n");
}

static void
ndjson_close(const struct Output *out)
{
    fflush(file);
    fclose(file);
}

struct OutputModule NdjsonOutput = {
    .name               = "ndjson",
    .need_file          = 1,
    .params             = NULL,
    .init_cb            = &ndjson_init,
    .result_cb          = &ndjson_result,
    .close_cb           = &ndjson_close,
    .desc =
        "NdjsonOutput save results in newline-delimited json(ndjson) format to "
        "specified file.\n"
        "NOTE: NdjsonOutput doesn't convert any escaped chars from result string"
        "and assumes all result string type except ports.",
};
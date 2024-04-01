#include "output-modules.h"

#include "../util/logger.h"
#include "../util/safe-string.h"
#include "../pixie/pixie-file.h"

extern struct OutputModule NdjsonOutput; /*for internal x-ref*/

static FILE *file;

static const char fmt_ndjson[] =
"{"
"\"time\":\"%s\","
"\"level\":%u,"
"\"ip_them\":\"%s\","
"\"port_them\":%u,"
"\"ip_me\":\"%s\","
"\"port_me\":%u,"
"\"classification\":\"%s\","
"\"reason\":\"%s\","
"\"report\":\"%s\""
"}"
"\n"
;

static char format_time[32];

static unsigned
ndjson_init(const struct Output *out)
{

    int err = pixie_fopen_shareable(
        &file, out->output_filename, out->is_append);

    if (err != 0 || file == NULL) {
        LOG(LEVEL_ERROR, "[-] NdjsonOutput: could not open file %s for %s.\n",
            out->output_filename, out->is_append?"appending":"writing");
        perror(out->output_filename);
        return -1;
    }

    return 1;
}

static void
ndjson_result(const struct Output *out, const struct OutputItem *item)
{
    if (item->level==Output_INFO && !out->is_show_info)
        return;
    if (item->level==Output_FAILURE && !out->is_show_failed)
        return;
    
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->ip_them);
    ipaddress_formatted_t ip_me_fmt   = ipaddress_fmt(item->ip_me);

    iso8601_time_str(format_time, sizeof(format_time), &item->timestamp);

    int err = fprintf(file, fmt_ndjson,
        format_time,
        item->level,
        ip_them_fmt.string,
        item->port_them,
        ip_me_fmt.string,
        item->port_me,
        item->classification,
        item->reason,
        item->report);
    
    if (err<0) {
        LOG(LEVEL_ERROR, "[-] NdjsonOutput: could not write result to file.\n");
    }
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
    .desc               =
        "NdjsonOutput save results in newline-delimited json(ndjson) format to "
        "specified file.",
};
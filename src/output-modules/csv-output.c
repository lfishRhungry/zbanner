#include "output-modules.h"

#include "../util/logger.h"
#include "../util/safe-string.h"
#include "../pixie/pixie-file.h"

extern struct OutputModule CsvOutput; /*for internal x-ref*/

static FILE *file;

static const char header_csv[] =
"time,"
"level,"
"ip_them,"
"port_them,"
"ip_me,"
"port_me,"
"classification,"
"reason,"
"report"
"\n"
;

static const char fmt_csv[] =
"\"%s\","
"%u,"
"\"%s\","
"%u,"
"\"%s\","
"%u,"
"\"%s\","
"\"%s\","
"\"%s\""
"\n"
;

static char format_time[32];

static int
csv_init(const struct Output *out)
{

    int err = pixie_fopen_shareable(
        &file, out->output_filename, out->is_append);

    if (err != 0 || file == NULL) {
        LOG(LEVEL_ERROR, "[-] CsvOutput: could not open file %s for %s.\n",
            out->output_filename, out->is_append?"appending":"writing");
        perror(out->output_filename);
        return -1;
    }

    err = fputs(header_csv, file);
    
    if (err<0) {
        LOG(LEVEL_ERROR, "[-] CsvOutput: could not write header to file.\n");
    }

    return 1;
}

static void
csv_result(const struct Output *out, const struct OutputItem *item)
{
    if (item->level==Output_INFO && !out->is_show_info)
        return;
    if (item->level==Output_FAILURE && !out->is_show_failed)
        return;
    
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->ip_them);
    ipaddress_formatted_t ip_me_fmt   = ipaddress_fmt(item->ip_me);

    iso8601_time_str(format_time, sizeof(format_time), &item->timestamp);

    int err = fprintf(file, fmt_csv,
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
        LOG(LEVEL_ERROR, "[-] CsvOutput: could not write result to file.\n");
    }
}

static void
csv_close(const struct Output *out)
{
    fflush(file);
    fclose(file);
}

struct OutputModule CsvOutput = {
    .name               = "csv",
    .need_file          = 1,
    .params             = NULL,
    .init_cb            = &csv_init,
    .result_cb          = &csv_result,
    .close_cb           = &csv_close,
    .desc               =
        "CsvOutput save results in Comma-seperated Values(csv) format to "
        "specified file.",
};
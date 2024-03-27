#include "output-modules.h"

#include "../util/logger.h"
#include "../pixie/pixie-file.h"

static char fmt_host[]   = "%s host: %-15s";
static char fmt_port[]   = " port: %-5u";
static char fmt_cls []   = " \"%s\"";
static char fmt_reason[] = " because of \"%s\"";
static char fmt_report[] = "  Report: %s";

extern struct OutputModule TextOutput; /*for internal x-ref*/

static FILE *file;

static int
text_init(const struct Output *out)
{

    int err = pixie_fopen_shareable(
        &file, out->output_filename, out->is_append);

    if (err != 0 || file == NULL) {
        LOG(LEVEL_ERROR, "[-] TextOutput: could not open file %s for %s.\n",
            out->output_filename, out->is_append?"appending":"writing");
        perror(out->output_filename);
        return -1;
    }

    return 1;
}

static void
text_result(const struct Output *out, const struct OutputItem *item)
{
    if (item->level==Output_INFO && !out->is_show_info)
        return;
    if (item->level==Output_FAILURE && !out->is_show_failed)
        return;
    
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->ip_them);

    int err = 0;

    switch (item->level)
    {
    case Output_SUCCESS:
        err = fprintf(file, fmt_host, "[+]", ip_them_fmt.string);
        break;
    case Output_FAILURE:
        err = fprintf(file, fmt_host, "[x]", ip_them_fmt.string);
        break;
    case Output_INFO:
        err = fprintf(file, fmt_host, "[*]", ip_them_fmt.string);
        break;
    default:
        return;
    }

    if (err<0) goto error;

    if (item->port_them) {
        err = fprintf(file, fmt_port, item->port_them);
        if (err<0) goto error;
    }

    if (item->classification[0]) {
        err = fprintf(file, fmt_cls, item->classification);
        if (err<0) goto error;
    }

    if (item->reason[0]) {
        err = fprintf(file, fmt_reason, item->reason);
        if (err<0) goto error;
    }

    if (item->report[0]) {
        err = fprintf(file, fmt_report, item->report);
        if (err<0) goto error;
    }

    err = fprintf(file, "\n");
    if (err<0) goto error;

    return;

error:

    LOG(LEVEL_ERROR, "[-] TextOutput: could not write result to file.\n");
}

static void
text_close(const struct Output *out)
{
    fflush(file);
    fclose(file);
}

struct OutputModule TextOutput = {
    .name               = "text",
    .need_file          = 1,
    .params             = NULL,
    .init_cb            = &text_init,
    .result_cb          = &text_result,
    .close_cb           = &text_close,
    .desc               =
        "TextOutput save results same as stdout to specified file without color.",
};
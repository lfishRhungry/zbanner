#include "output-modules.h"

#include "../util-out/logger.h"
#include "../pixie/pixie-file.h"

static const char fmt_host[]       = "%s host: %s";
static const char fmt_port[]       = " port: %u";
static const char fmt_proto[]      = " in %s";
static const char fmt_cls []       = " is \"%s\"";
static const char fmt_reason[]     = " because \"%s\"";
static const char fmt_report_str[] = ",  %s: \"%s\"";
static const char fmt_report_num[] = ",  %s: %s";

extern struct OutputModule TextOutput; /*for internal x-ref*/

static FILE *file;

static bool
text_init(const struct Output *out)
{

    int err = pixie_fopen_shareable(
        &file, out->output_filename, out->is_append);

    if (err != 0 || file == NULL) {
        LOG(LEVEL_ERROR, "TextOutput: could not open file %s for %s.\n",
            out->output_filename, out->is_append?"appending":"writing");
        perror(out->output_filename);
        return false;
    }

    return true;
}

static void
text_result(struct OutputItem *item)
{
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->ip_them);

    bool output_port = (item->ip_proto==IP_PROTO_TCP
        || item->ip_proto==IP_PROTO_UDP || item->ip_proto==IP_PROTO_SCTP);

    int err = 0;

    switch (item->level)
    {
    case OP_SUCCESS:
        err = fprintf(file, fmt_host, "[+]", ip_them_fmt.string);
        break;
    case OP_FAILURE:
        err = fprintf(file, fmt_host, "[x]", ip_them_fmt.string);
        break;
    case OP_INFO:
        err = fprintf(file, fmt_host, "[*]", ip_them_fmt.string);
        break;
    default:
        err = fprintf(file, fmt_host, "[?]", ip_them_fmt.string);
    }

    if (err<0) goto error;

    if (output_port) {
        err = fprintf(file, fmt_port, item->port_them);
        if (err<0) goto error;
    }

    err = fprintf(file, fmt_proto, ip_proto_to_string(item->ip_proto));
    if (err<0) goto error;

    if (item->classification[0]) {
        err = fprintf(file, fmt_cls, item->classification);
        if (err<0) goto error;
    }

    if (item->reason[0]) {
        err = fprintf(file, fmt_reason, item->reason);
        if (err<0) goto error;
    }

    struct DataLink *pre = item->report.link;
    while (pre->next) {
        fprintf(file,
            pre->next->is_number?fmt_report_num:fmt_report_str,
            pre->next->name, pre->next->data);
        pre = pre->next;
    }

    err = fprintf(file, "\n");
    if (err<0) goto error;

    return;

error:
    LOG(LEVEL_ERROR, "TextOutput: could not write result to file.\n");
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
    .desc =
        "TextOutput save results same as stdout to specified file without color.",
};
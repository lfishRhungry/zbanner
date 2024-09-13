#include "output-modules.h"

#include <string.h>
#include "../util-out/logger.h"
#include "../pixie/pixie-file.h"

static const char fmt_host[]          = "%s host: %s";
static const char fmt_port[]          = " port: %u";
static const char fmt_proto[]         = " in %s";
static const char fmt_cls[]           = " is \"%s\"";
static const char fmt_reason[]        = " because \"%s\"";
static const char fmt_report_str[]    = ",  %s: \"%s\"";
static const char fmt_report_int[]    = ",  %s: %" PRIu64;
static const char fmt_report_double[] = ", %s: %.2f";
static const char fmt_report_true[]   = ", %s: true";
static const char fmt_report_false[]  = ", %s: false";

extern Output TextOutput; /*for internal x-ref*/

static FILE *file;

static bool text_init(const OutConf *out) {
    /*a convention*/
    if (out->output_filename[0] == '-' && strlen(out->output_filename) == 1) {
        file = stdout;
        return true;
    }

    int err =
        pixie_fopen_shareable(&file, out->output_filename, out->is_append);

    if (err != 0 || file == NULL) {
        LOG(LEVEL_ERROR, "TextOutput: could not open file %s for %s.\n",
            out->output_filename, out->is_append ? "appending" : "writing");
        perror(out->output_filename);
        return false;
    }

    return true;
}

static void text_result(OutItem *item) {
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->target.ip_them);

    bool output_port = (item->target.ip_proto == IP_PROTO_TCP ||
                        item->target.ip_proto == IP_PROTO_UDP ||
                        item->target.ip_proto == IP_PROTO_SCTP);

    int err = 0;

    switch (item->level) {
        case OUT_SUCCESS:
            err = fprintf(file, fmt_host, "[+]", ip_them_fmt.string);
            break;
        case OUT_FAILURE:
            err = fprintf(file, fmt_host, "[x]", ip_them_fmt.string);
            break;
        case OUT_INFO:
            err = fprintf(file, fmt_host, "[*]", ip_them_fmt.string);
            break;
        default:
            err = fprintf(file, fmt_host, "[?]", ip_them_fmt.string);
    }

    if (err < 0)
        goto error;

    if (output_port) {
        err = fprintf(file, fmt_port, item->target.port_them);
        if (err < 0)
            goto error;
    }

    err = fprintf(file, fmt_proto, ip_proto_to_string(item->target.ip_proto));
    if (err < 0)
        goto error;

    if (item->classification[0]) {
        err = fprintf(file, fmt_cls, item->classification);
        if (err < 0)
            goto error;
    }

    if (item->reason[0]) {
        err = fprintf(file, fmt_reason, item->reason);
        if (err < 0)
            goto error;
    }

    DataLink *pre = item->report.link;
    while (pre->next) {
        if (pre->next->link_type == LinkType_Data) {
            fprintf(file, fmt_report_str, pre->next->name,
                    pre->next->value_data);
        } else if (pre->next->link_type == LinkType_Int) {
            fprintf(file, fmt_report_int, pre->next->name,
                    pre->next->value_int);
        } else if (pre->next->link_type == LinkType_Double) {
            fprintf(file, fmt_report_double, pre->next->name,
                    pre->next->value_double);
        } else if (pre->next->link_type == LinkType_Bool) {
            fprintf(file,
                    pre->next->value_bool ? fmt_report_true : fmt_report_false,
                    pre->next->name);
        }
        pre = pre->next;
    }

    err = fprintf(file, "\n");
    if (err < 0)
        goto error;

    return;

error:
    LOG(LEVEL_ERROR, "TextOutput: could not write result to file.\n");
}

static void text_close(const OutConf *out) {
    fflush(file);
    if (file != stdout) {
        fclose(file);
    }
}

Output TextOutput = {
    .name      = "text",
    .need_file = 1,
    .params    = NULL,
    .desc = "TextOutput save results same as stdout to specified file without "
            "color.",

    .init_cb   = &text_init,
    .result_cb = &text_result,
    .close_cb  = &text_close,
};
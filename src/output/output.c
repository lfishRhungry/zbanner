#include <stdio.h>

#include "output.h"
#include "../pixie/pixie-file.h"
#include "../util/logger.h"

static char fmt_success_host[] = "%s on host: %-15s";
static char fmt_port[] = " port: %-5u";
static char fmt_classification[] = " \"%s\"";
static char fmt_reason[] = " because of \"%s\"";
static char fmt_report[] = ". Report: %s";

void
output_init(struct Output *output)
{
    if (output->output_filename[0]) {
        int err = pixie_fopen_shareable(
            &output->output_file, output->output_filename, output->is_append);
        if (err != 0 || output->output_file == NULL) {
            LOG(0, "[-] output: could not open file %s for %s\n",
                output->output_filename, output->is_append?"appending":"writing");
            LOG(0, "            output results to stdout now.\n");
            perror(output->output_filename);
            output->output_file = NULL;
        }
    }
}

/*Some special processes should be done when output to stdout for avoiding mess*/
static void
output_result_to_stdout(
    const struct Output *output,
    const struct OutputItem *item)
{
    if (!item->is_success && !output->is_show_failed)
        return;

    // ipaddress_formatted_t ip_me_fmt = ipaddress_fmt(item->ip_me);
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->ip_them);

    unsigned count = 0;

    count = fprintf(stdout, fmt_success_host,
        item->is_success?"Success":"Failure",
        ip_them_fmt.string);
    
    if (item->port_them) {
        count += fprintf(stdout, fmt_port, item->port_them);
    }

    if (item->classification[0]) {
        count += fprintf(stdout, fmt_classification, item->classification);
    }

    if (item->reason[0]) {
        count += fprintf(stdout, fmt_reason, item->reason);
    }

    if (item->report[0]) {
        count += fprintf(stdout, fmt_report, item->report);
    }
    
    if (count < 90)
            fprintf(stdout, "%.*s", (int)(89-count),
                    "                                                  "
                    "                                                  ");

    fprintf(stdout, "\n");
    fflush(stdout);
}

static void
output_result_to_file(
    const struct Output *output,
    const struct OutputItem *item)
{
    if (!item->is_success && !output->is_show_failed)
        return;
    
    FILE *fp = output->output_file;

    // ipaddress_formatted_t ip_me_fmt = ipaddress_fmt(item->ip_me);
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->ip_them);

    unsigned count = 0;

    count = fprintf(fp, fmt_success_host,
        item->is_success?"Success":"Failure",
        ip_them_fmt.string);
    
    if (item->port_them) {
        count += fprintf(fp, fmt_port, item->port_them);
    }

    if (item->classification[0]) {
        count += fprintf(fp, fmt_classification, item->classification);
    }

    if (item->reason[0]) {
        count += fprintf(fp, fmt_reason, item->reason);
    }

    if (item->report[0]) {
        count += fprintf(fp, fmt_report, item->report);
    }

    fprintf(fp, "\n");
}

void
output_result(
    const struct Output *output,
    const struct OutputItem *item)
{
    if (item->no_output)
        return;

    if (output->output_file) {
        output_result_to_file(output, item);
        if (output->is_interactive) {
            output_result_to_stdout(output, item);
        }
    } else {
        output_result_to_stdout(output, item);
    }
}

void
output_close(struct Output *output)
{
    if (output->output_file) {
        fflush(output->output_file);
        fclose(output->output_file);
    }
}
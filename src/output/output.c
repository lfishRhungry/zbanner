#include <stdio.h>

#include "output.h"
#include "../pixie/pixie-file.h"
#include "../util/logger.h"

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
    const struct PreprocessedInfo *parsed,
    time_t timestamp, unsigned successed,
    const char *classification, const char *report)
{
    if (!successed && !output->is_show_failed)
        return;

    ipaddress ip_me = parsed->dst_ip;
    ipaddress ip_them = parsed->src_ip;
    unsigned port_me = parsed->port_dst;
    unsigned port_them = parsed->port_src;

    ipaddress_formatted_t ip_me_fmt = ipaddress_fmt(ip_me);
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(ip_them);

    unsigned count = 0;

    if (parsed->found==FOUND_ICMP || parsed->found==FOUND_ARP) {
        char fmt[] = "%s on host: %-15s because of \"%s\"";
        count = fprintf(stdout, fmt,
            successed?"Success":"Failure",
            ip_them_fmt.string,
            classification);
    } else {
        char fmt[] = "%s on host: %-15s port: %-5u because of \"%s\"";
        count = fprintf(stdout, fmt,
            successed?"Success":"Failure",
            ip_them_fmt.string, port_them,
            classification);
    }
    
    if (report[0]) {
        count += fprintf(stdout, ". Report: [%s]", report);
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
    const struct PreprocessedInfo *parsed,
    time_t timestamp, unsigned successed,
    const char *classification, const char *report)
{
    if (!successed && !output->is_show_failed)
        return;
    
    FILE *fp = output->output_file;

    ipaddress ip_me = parsed->dst_ip;
    ipaddress ip_them = parsed->src_ip;
    unsigned port_me = parsed->port_dst;
    unsigned port_them = parsed->port_src;

    ipaddress_formatted_t ip_me_fmt = ipaddress_fmt(ip_me);
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(ip_them);

    unsigned count = 0;

    if (parsed->found==FOUND_ICMP || parsed->found==FOUND_ARP) {
        char fmt[] = "%s on host: %-15s because of \"%s\"";
        count = fprintf(fp, fmt,
            successed?"Success":"Failure",
            ip_them_fmt.string,
            classification);
    } else {
        char fmt[] = "%s on host: %-15s port: %-5u because of \"%s\"";
        count = fprintf(fp, fmt,
            successed?"Success":"Failure",
            ip_them_fmt.string, port_them,
            classification);
    }
    
    if (report[0]) {
        count += fprintf(fp, ". Report: [%s]", report);
    }

    fprintf(fp, "\n");
}

void
output_result(
    const struct Output *output,
    const struct PreprocessedInfo *parsed,
    time_t timestamp, unsigned successed,
    const char *classification, const char *report)
{
    if (output->output_file) {
        output_result_to_file(output, parsed, timestamp,
            successed, classification, report);
        if (output->is_interactive) {
            output_result_to_stdout(output, parsed, timestamp,
                successed, classification, report);
        }
    } else {
        output_result_to_stdout(output, parsed, timestamp,
            successed, classification, report);
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
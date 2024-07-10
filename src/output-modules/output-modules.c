#include <stdio.h>
#include <string.h>

#include "output-modules.h"
#include "../globals.h"
#include "../pixie/pixie-file.h"
#include "../pixie/pixie-threads.h"
#include "../util-out/logger.h"
#include "../util-out/xprint.h"
#include "../util-data/fine-malloc.h"


extern Output TextOutput;
extern Output NdjsonOutput;
extern Output CsvOutput;
extern Output ListOutput;
extern Output NullOutput;
//! REGIST YOUR OUTPUT MODULE HERE

static Output *output_modules_list[] = {
    &TextOutput,
    &NdjsonOutput,
    &CsvOutput,
    &ListOutput,
    &NullOutput,
    //! REGIST YOUR OUTPUT MODULE HERE
};


const char *
output_level_to_string(OutLevel level)
{
    switch (level) {
        case OUT_INFO:       return "information";
        case OUT_FAILURE:    return "failed";
        case OUT_SUCCESS:    return "success";

        default:
            return "unknown";
    }
}


Output *get_output_module_by_name(const char *name)
{
    int len = (int)ARRAY_SIZE(output_modules_list);
    for (int i = 0; i < len; i++) {
        if (!strcmp(output_modules_list[i]->name, name)) {
            return output_modules_list[i];
        }
    }
    return NULL;
}

void list_all_output_modules()
{
    int len = (int)ARRAY_SIZE(output_modules_list);

    printf("\n");
    printf(XPRINT_STAR_LINE);
    printf("\n");
    printf("      Now contains [%d] OutputModules\n", len);
    printf(XPRINT_STAR_LINE);
    printf("\n");
    printf("\n");

    for (int i = 0; i < len; i++) {
        printf(XPRINT_DASH_LINE);
        printf("\n");
        printf("\n");
        printf("  Name of OutputModule: %s\n", output_modules_list[i]->name);
        printf("  Description:\n");
        xprint(output_modules_list[i]->desc, 6, 80);
        printf("\n");
        printf("\n");
    }
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
}

void help_output_module(Output *module)
{
    if (!module) {
        LOG(LEVEL_ERROR, "No specified output module.\n");
        return;
    }

    printf("\n");
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
    printf("  Name of OutputModule: %s\n", module->name);
    printf("  Need to Specify file: %s\n", module->need_file?"true":"false");
    printf("\n");
    printf("  Description:\n");
    xprint(module->desc, 6, 80);
    printf("\n");
    printf("\n");
    if (module->params) {
        for (unsigned j=0; module->params[j].name; j++) {

            if (!module->params[j].help_text)
                continue;

            printf("  --%s", module->params[j].name);
            for (unsigned k=0; module->params[j].alt_names[k]; k++) {
                printf(", --%s", module->params[j].alt_names[k]);
            }
            printf("\n");
            xprint(module->params[j].help_text, 6, 80);
            printf("\n\n");
        }
    }
    printf("\n");
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
}


static const char fmt_host[]       = "%s host: %-15s";
static const char fmt_port[]       = " port: %-5u";
static const char fmt_cls []       = " \"%s\"";
static const char fmt_reason[]     = " because \"%s\"";
static const char fmt_report_str[] = ",  "XPRINT_CH_COLOR_YELLOW"%s: \"%s\"";
static const char fmt_report_num[] = ",  "XPRINT_CH_COLOR_YELLOW"%s: %s";

bool output_init(OutConf *out_conf)
{
    if (out_conf->output_module) {

        if (out_conf->output_module->need_file && !out_conf->output_filename[0]) {
            LOG(LEVEL_ERROR,
                "OutputModule %s need to specify output file name by `--output-file`.\n",
                out_conf->output_module->name);
            return false;
        }

        if (out_conf->output_module->params && out_conf->output_args) {
            if (set_parameters_from_substring(NULL,
                out_conf->output_module->params, out_conf->output_args)) {
                LOG(LEVEL_ERROR, "errors happened in sub param parsing of OutputModule.\n");
                return false;
            }
        }

        if (!out_conf->output_module->init_cb(out_conf)) {
            LOG(LEVEL_ERROR, "errors happened in %s initing.\n",
                out_conf->output_module->name);
            return false;
        }
    }

    out_conf->stdout_mutex = pixie_create_mutex();
    out_conf->module_mutex = pixie_create_mutex();
    out_conf->succ_mutex   = pixie_create_mutex();
    out_conf->fail_mutex   = pixie_create_mutex();
    out_conf->info_mutex   = pixie_create_mutex();

    return true;
}

/*Some special processes should be done when output to stdout for avoiding mess*/
static void
output_result_to_stdout(OutItem *item)
{
    // ipaddress_formatted_t ip_me_fmt = ipaddress_fmt(item->ip_me);
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->ip_them);

    bool output_port = (item->ip_proto==IP_PROTO_TCP
        || item->ip_proto==IP_PROTO_UDP || item->ip_proto==IP_PROTO_SCTP);

    unsigned count = 0;

    switch (item->level)
    {
    case OUT_SUCCESS:
        count = fprintf(stdout, fmt_host,
            XPRINT_CH_COLOR_GREEN"[+]", ip_them_fmt.string);
        break;
    case OUT_FAILURE:
        count = fprintf(stdout, fmt_host,
            XPRINT_CH_COLOR_RED"[x]", ip_them_fmt.string);
        break;
    case OUT_INFO:
        count = fprintf(stdout, fmt_host,
            XPRINT_CH_COLOR_CYAN"[*]", ip_them_fmt.string);
        break;
    default:
        count = fprintf(stdout, fmt_host,
            "[?]", ip_them_fmt.string);
    }

    if (output_port) {
        count += fprintf(stdout, fmt_port, item->port_them);
    }

    if (item->classification[0]) {
        count += fprintf(stdout, fmt_cls, item->classification);
    }

    if (item->reason[0]) {
        count += fprintf(stdout, fmt_reason, item->reason);
    }

    DataLink *pre = item->report.link;
    while (pre->next) {
        count += fprintf(stdout,
            pre->next->is_number?fmt_report_num:fmt_report_str,
            pre->next->name, pre->next->data);
        pre = pre->next;
    }

    if (count < 120)
        fprintf(stdout, "%*s", (int)(120-count), "");

    fprintf(stdout, XPRINT_COLOR_RESET"\n");
    fflush(stdout);
}

void
output_result(const OutConf *out, OutItem *item)
{
    if (item->no_output)
        goto error0;

    if (!item->timestamp)
        ((OutItem *)item)->timestamp = global_now;

    if (item->level==OUT_SUCCESS) {
        pixie_acquire_mutex(out->succ_mutex);
        ((OutConf *)out)->total_successed++;
        pixie_release_mutex(out->succ_mutex);
    }

    if (item->level==OUT_FAILURE) {
        pixie_acquire_mutex(out->fail_mutex);
        ((OutConf *)out)->total_failed++;
        pixie_release_mutex(out->fail_mutex);
    }

    if (item->level==OUT_INFO) {
        pixie_acquire_mutex(out->info_mutex);
        ((OutConf *)out)->total_info++;
        pixie_release_mutex(out->info_mutex);
    }

    if (item->level==OUT_INFO && !out->is_show_info)
        goto error0;
    if (item->level==OUT_FAILURE && !out->is_show_failed)
        goto error0;
    if (item->level==OUT_SUCCESS && out->no_show_success)
        goto error0;

    if (out->output_module) {
        pixie_acquire_mutex(out->module_mutex);
        out->output_module->result_cb(item);
        pixie_release_mutex(out->module_mutex);
        if (out->is_interactive) {
            pixie_acquire_mutex(out->stdout_mutex);
            output_result_to_stdout(item);
            pixie_release_mutex(out->stdout_mutex);
        }
    } else {
        pixie_acquire_mutex(out->stdout_mutex);
        output_result_to_stdout(item);
        pixie_release_mutex(out->stdout_mutex);
    }

error0:
    dach_release(&item->report);
}

void output_close(OutConf *out_conf)
{
    if (out_conf->output_module) {
        out_conf->output_module->close_cb(out_conf);
    }

    pixie_delete_mutex(out_conf->stdout_mutex);
    pixie_delete_mutex(out_conf->module_mutex);
    pixie_delete_mutex(out_conf->succ_mutex);
    pixie_delete_mutex(out_conf->fail_mutex);
    pixie_delete_mutex(out_conf->info_mutex);
}

bool output_init_nothing(const OutConf *out_conf)
{
    return true;
}

void output_result_nothing(OutItem *item) {}

void output_close_nothing(const OutConf *out_conf) {}
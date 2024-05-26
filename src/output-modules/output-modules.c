#include <stdio.h>
#include <string.h>

#include "output-modules.h"
#include "../globals.h"
#include "../pixie/pixie-file.h"
#include "../pixie/pixie-threads.h"
#include "../util-out/logger.h"
#include "../util-out/xprint.h"
#include "../util-data/fine-malloc.h"


extern struct OutputModule TextOutput;
extern struct OutputModule NdjsonOutput;
extern struct OutputModule CsvOutput;
extern struct OutputModule ListOutput;
extern struct OutputModule NullOutput;
//! REGIST YOUR OUTPUT MODULE HERE

static struct OutputModule *output_modules_list[] = {
    &TextOutput,
    &NdjsonOutput,
    &CsvOutput,
    &ListOutput,
    &NullOutput,
    //! REGIST YOUR OUTPUT MODULE HERE
};


const char *
output_level_to_string(enum OutputLevel level)
{
    switch (level) {
        case Output_INFO:       return "information";
        case Output_FAILURE:    return "failed";
        case Output_SUCCESS:    return "success";

        default:
            return "unknown";
    }
}


struct OutputModule *get_output_module_by_name(const char *name)
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
        printf("  Need to Specify file: %s\n", output_modules_list[i]->need_file?"true":"false");
        printf("\n");
        printf("  Description:\n");
        xprint(output_modules_list[i]->desc, 6, 80);
        printf("\n");
        printf("\n");
        if (output_modules_list[i]->params) {
            for (unsigned j=0; output_modules_list[i]->params[j].name; j++) {

                if (!output_modules_list[i]->params[j].help_text)
                    continue;

                printf("  --%s", output_modules_list[i]->params[j].name);
                for (unsigned k=0; output_modules_list[i]->params[j].alt_names[k]; k++) {
                    printf(", --%s", output_modules_list[i]->params[j].alt_names[k]);
                }
                printf("\n");
                xprint(output_modules_list[i]->params[j].help_text, 6, 80);
                printf("\n\n");
            }
        }
        printf("\n");
    }
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

bool
output_init(struct Output *out)
{
    if (out->output_module) {

        if (out->output_module->need_file && !out->output_filename[0]) {
            LOG(LEVEL_ERROR,
                "[-] OutputModule %s need to specify output file name by `--output-file`.\n",
                out->output_module->name);
            return false;
        }

        if (out->output_module->params) {
            if (set_parameters_from_substring(NULL,
                out->output_module->params, out->output_args)) {
                LOG(LEVEL_ERROR, "FAIL: errors happened in sub param parsing of OutputModule.\n");
                return false;
            }
        }

        if (!out->output_module->init_cb(out)) {
            LOG(LEVEL_ERROR, "[-] FAIL: errors happened in %s initing.\n",
                out->output_module->name);
            return false;
        }
    }

    out->stdout_mutex = pixie_create_mutex();
    out->module_mutex = pixie_create_mutex();
    out->succ_mutex   = pixie_create_mutex();
    out->fail_mutex   = pixie_create_mutex();
    out->info_mutex   = pixie_create_mutex();

    return true;
}

/*Some special processes should be done when output to stdout for avoiding mess*/
static void
output_result_to_stdout(struct OutputItem *item)
{
    // ipaddress_formatted_t ip_me_fmt = ipaddress_fmt(item->ip_me);
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->ip_them);

    unsigned count = 0;

    switch (item->level)
    {
    case Output_SUCCESS:
        count = fprintf(stdout, fmt_host,
            XPRINT_CH_COLOR_GREEN"[+]", ip_them_fmt.string);
        break;
    case Output_FAILURE:
        count = fprintf(stdout, fmt_host,
            XPRINT_CH_COLOR_RED"[x]", ip_them_fmt.string);
        break;
    case Output_INFO:
        count = fprintf(stdout, fmt_host,
            XPRINT_CH_COLOR_CYAN"[*]", ip_them_fmt.string);
        break;
    default:
        return;
    }

    if (item->port_them) {
        count += fprintf(stdout, fmt_port, item->port_them);
    }

    if (item->classification[0]) {
        count += fprintf(stdout, fmt_cls, item->classification);
    }

    if (item->reason[0]) {
        count += fprintf(stdout, fmt_reason, item->reason);
    }

    struct DataLink *pre = item->report.link;
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
output_result(const struct Output *out, struct OutputItem *item)
{
    if (item->no_output)
        return;

    if (!item->timestamp)
        ((struct OutputItem *)item)->timestamp = global_now;

    if (item->level==Output_SUCCESS) {
        pixie_acquire_mutex(out->succ_mutex);
        ((struct Output *)out)->total_successed++;
        pixie_release_mutex(out->succ_mutex);
    }

    if (item->level==Output_FAILURE) {
        pixie_acquire_mutex(out->fail_mutex);
        ((struct Output *)out)->total_failed++;
        pixie_release_mutex(out->fail_mutex);
    }

    if (item->level==Output_INFO) {
        pixie_acquire_mutex(out->info_mutex);
        ((struct Output *)out)->total_info++;
        pixie_release_mutex(out->info_mutex);
    }

    if (item->level==Output_INFO && !out->is_show_info)
        return;
    if (item->level==Output_FAILURE && !out->is_show_failed)
        return;
    if (item->level==Output_SUCCESS && out->no_show_success)
        return;

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

    dach_release(&item->report);
}

void
output_close(struct Output *out)
{
    if (out->output_module) {
        out->output_module->close_cb(out);
    }

    pixie_delete_mutex(out->stdout_mutex);
    pixie_delete_mutex(out->module_mutex);
    pixie_delete_mutex(out->succ_mutex);
    pixie_delete_mutex(out->fail_mutex);
    pixie_delete_mutex(out->info_mutex);
}

bool output_init_nothing(const struct Output *out)
{
    return true;
}

void output_result_nothing(struct OutputItem *item) {}

void output_close_nothing(const struct Output *out) {}
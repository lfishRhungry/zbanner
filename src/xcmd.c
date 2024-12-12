#include "xcmd.h"

#include "scan-modules/scan-modules.h"
#include "version.h"
#include "crossline/crossline.h"
#include "target/target-cookie.h"

#include "util-out/logger.h"
#include "util-out/xprint.h"
#include "util-data/safe-string.h"
#include "util-data/fine-malloc.h"
#include "xconf.h"
#include <openssl/ec.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define READLINE_SIZE 65535

extern ConfParam  config_parameters[];
extern Scanner   *scan_modules_list[];
extern Probe     *probe_modules_list[];
extern Output    *output_modules_list[];
extern Generator *generate_modules_list[];

typedef enum Action_Res {
    ActRes_Next,   /*handle next readline*/
    ActRes_Prefix, /*continue to handle param after prefix*/
    ActRes_Finish, /*let xcmd to exit of readline*/
} ActRes;

/**
 * Do actions for a command.
 * @return false if need to exit interactive cmd mode.
 */
typedef ActRes (*xcmd_action)(void *conf);

typedef struct {
    char       *cmd;
    char       *hint; /*short help*/
    xcmd_action action;
} XCmd;

static ActRes ACT_run(void *conf) { return ActRes_Finish; }

static ActRes ACT_exit(void *conf) {
    char line[128];

    printf("Are you sure to exit " XTATE_NAME "? [y/N]: ");

    if (NULL == fgets(line, 128, stdin)) {
        LOG(LEVEL_ERROR, "(%s) failed input.\n", __func__);
        return ActRes_Next;
    }

    if ((line[0] == 'y' || line[0] == 'Y') && line[1] == '\n') {
        LOG(LEVEL_HINT, "See you next time, bye~\n");
        exit(0);
    }

    return ActRes_Next;
}

static ActRes ACT_clear(void *conf) {
    XConf *xconf = conf;
    char   line[128];

    printf("Are you sure to clear configuration of " XTATE_NAME "? [y/N]: ");

    if (NULL == fgets(line, 128, stdin)) {
        LOG(LEVEL_ERROR, "(%s) failed input.\n", __func__);
        return ActRes_Next;
    }

    if ((line[0] == 'y' || line[0] == 'Y') && line[1] == '\n') {
        xconf_global_refresh(xconf);
        LOG(LEVEL_HINT, "Configuration cleared!\n");
    }

    return ActRes_Next;
}

static ActRes ACT_version(void *conf) {
    xconf_print_version();
    return ActRes_Next;
}

static ActRes ACT_echo(void *conf) {
    XConf *xconf = conf;
    xconf_echo(xconf, stdout);
    return ActRes_Next;
}

static ActRes ACT_echo_all(void *conf) {
    XConf *xconf    = conf;
    xconf->echo_all = 1;
    xconf_echo(xconf, stdout);
    return ActRes_Next;
}

static ActRes ACT_help(void *conf) {
    xprint(XTATE_NAME_TITLE_CASE
           "'s interactive mode allows users to set param and do scan research "
           "in a more comfortable way.\n"
           "We can set params in key/value's way one by one and adjust them "
           "conveniently. Also, we can watch help text of all modules and "
           "global params by `help-xxx` commands.\n"
           "More important, interactive mode supports auto completion by <TAB> "
           "for commands. This could be used to check concise help, too.\n",
           4, 80);
    return ActRes_Next;
}

static ActRes ACT_update_seed(void *conf) {
    XConf *xconf = conf;

    uint64_t old = xconf->seed;
    xconf->seed  = get_one_entropy();
    LOG(LEVEL_HINT, "Seed updated from %" PRIu64 " to %" PRIu64 "\n", old,
        xconf->seed);
    return ActRes_Next;
}

static ActRes ACT_list_param(void *conf) {
    xconf_print_help();
    return ActRes_Next;
}

static ActRes ACT_list_scan(void *conf) {
    list_all_scan_modules();
    return ActRes_Next;
}

static ActRes ACT_list_probe(void *conf) {
    list_all_probe_modules();
    return ActRes_Next;
}

static ActRes ACT_list_out(void *conf) {
    list_all_output_modules();
    return ActRes_Next;
}

static ActRes ACT_list_gen(void *conf) {
    list_all_generate_modules();
    return ActRes_Next;
}

static ActRes ACT_prefix(void *conf) { return ActRes_Prefix; }

#define PRE_SET_PARAM     "set"
#define PRE_HELP_PARAM    "help-param"
#define PRE_HELP_SCAN     "help-scan"
#define PRE_HELP_PROBE    "help-probe"
#define PRE_HELP_OUT      "help-out"
#define PRE_HELP_GEN      "help-gen"
#define PRE_SEARCH_PARAM  "search-param"
#define PRE_SEARCH_MODULE "search-module"

static const XCmd config_cmd[] = {
    {"run", "Execute " XTATE_NAME " with configured parmas.", ACT_run},
    {PRE_SET_PARAM,
     "Set a global param of " XTATE_NAME_TITLE_CASE " like `set key = value`.",
     ACT_prefix},
    {"echo", "Print current configuration of " XTATE_NAME_TITLE_CASE, ACT_echo},
    {"echo-all", "Print all configuration of " XTATE_NAME_TITLE_CASE,
     ACT_echo_all},
    {"clear", "Refresh configuration to default except `seed`.", ACT_clear},
    {"exit", "Exit the program directly.", ACT_exit},
    {PRE_SEARCH_PARAM,
     "Fuzzy search global params of " XTATE_NAME_TITLE_CASE ".", ACT_prefix},
    {"list-param", "List all global params and detailed help.", ACT_list_param},
    {PRE_HELP_PARAM, "Print detailed help of a specified global param.",
     ACT_prefix},
    {PRE_SEARCH_MODULE, "Fuzzy search modules of " XTATE_NAME_TITLE_CASE ".",
     ACT_prefix},
    {"list-scan", "List all scan modules.", ACT_list_scan},
    {PRE_HELP_SCAN, "Print detailed help of a specified Scan Module.",
     ACT_prefix},
    {"list-probe", "List all probe modules.", ACT_list_probe},
    {PRE_HELP_PROBE, "Print detailed help of a specified Probe Module.",
     ACT_prefix},
    {"list-out", "List all output modules.", ACT_list_out},
    {PRE_HELP_OUT, "Print detailed help of a specified Output Module.",
     ACT_prefix},
    {"list-gen", "List all generate modules.", ACT_list_gen},
    {PRE_HELP_GEN, "Print detailed help of a specified Generate Module.",
     ACT_prefix},
    {"update-seed", "Update the global seed to a new rand number.",
     ACT_update_seed},
    {"version", "Print version info of " XTATE_NAME_TITLE_CASE, ACT_version},
    {"help", "Print help information for interactive command mode.", ACT_help},

    {0}};

/**
 * Handle subcommand for prefix command
 * @return false if need to exit interactive cmd mode.
 */
typedef void (*xcmd_handle)(void *conf, char *subcmd, size_t len);

typedef struct {
    char                         *prefix;
    xcmd_handle                   handle;
    crossline_completion_callback completion;
} XPrefix;

static void HDL_set(void *conf, char *subcmd, size_t len) {
    XConf *xconf = conf;
    int    err;
    err = xconf_set_parameter_in_kv(xconf, subcmd, len);
    if (err == -1) {
        LOG(LEVEL_ERROR, "failed to set the param.\n");
    } else if (err == 1) {
        LOG(LEVEL_HINT, "input was not a command or param conf.\n");
        LOG(LEVEL_HINT, "please set param in \"set key = value\" format.\n");
    } else if (err == 2) {
        LOG(LEVEL_HINT, "invalid param conf format.\n");
        LOG(LEVEL_HINT, "please set param like \"set key = "
                        "value\".\n");
    } else {
        LOG(LEVEL_HINT, "set param successfully.\n");
    }
}

static void HDL_help_param(void *conf, char *subcmd, size_t len) {
    xconf_help_param(subcmd);
}

static void HDL_help_scan(void *conf, char *subcmd, size_t len) {
    Scanner *scan = get_scan_module_by_name(subcmd);
    if (!scan) {
        LOG(LEVEL_ERROR, "no such scan module named %s\n", subcmd);
        return;
    }

    help_scan_module(scan);
}

static void HDL_help_probe(void *conf, char *subcmd, size_t len) {
    Probe *probe = get_probe_module_by_name(subcmd);
    if (!probe) {
        LOG(LEVEL_ERROR, "no such probe module named %s\n", subcmd);
        return;
    }

    help_probe_module(probe);
}

static void HDL_help_out(void *conf, char *subcmd, size_t len) {
    Output *output = get_output_module_by_name(subcmd);
    if (!output) {
        LOG(LEVEL_ERROR, "no such output module named %s\n", subcmd);
        return;
    }

    help_output_module(output);
}

static void HDL_help_gen(void *conf, char *subcmd, size_t len) {
    Generator *gen = get_generate_module_by_name(subcmd);
    if (!gen) {
        LOG(LEVEL_ERROR, "no such generate module named %s\n", subcmd);
        return;
    }

    help_generate_module(gen);
}

static void HDL_search_param(void *conf, char *subcmd, size_t len) {
    xconf_search_param(subcmd);
}

static void HDL_search_module(void *conf, char *subcmd, size_t len) {
    xconf_search_module(subcmd);
}

static void CPL_scan_module(const char              *cmd,
                            crossline_completions_t *p_completion) {
    crossline_color_e cmd_color = CROSSLINE_FGCOLOR_YELLOW |
                                  CROSSLINE_FGCOLOR_BRIGHT |
                                  CROSSLINE_BGCOLOR_DEFAULT;
    crossline_color_e help_color = CROSSLINE_COLOR_DEFAULT;
    for (unsigned i = 0; scan_modules_list[i]; i++) {
        if (!strncasecmp(scan_modules_list[i]->name, cmd, strlen(cmd))) {
            crossline_completion_add_color(
                p_completion, scan_modules_list[i]->name, cmd_color,
                scan_modules_list[i]->short_desc
                    ? scan_modules_list[i]->short_desc
                    : scan_modules_list[i]->desc,
                help_color);
        }
    }
}

static void CPL_probe_module(const char              *cmd,
                             crossline_completions_t *p_completion) {
    crossline_color_e cmd_color = CROSSLINE_FGCOLOR_YELLOW |
                                  CROSSLINE_FGCOLOR_BRIGHT |
                                  CROSSLINE_BGCOLOR_DEFAULT;
    crossline_color_e help_color = CROSSLINE_COLOR_DEFAULT;
    for (unsigned i = 0; probe_modules_list[i]; i++) {
        if (!strncasecmp(probe_modules_list[i]->name, cmd, strlen(cmd))) {
            crossline_completion_add_color(
                p_completion, probe_modules_list[i]->name, cmd_color,
                probe_modules_list[i]->short_desc
                    ? probe_modules_list[i]->short_desc
                    : probe_modules_list[i]->desc,
                help_color);
        }
    }
}

static void CPL_output_module(const char              *cmd,
                              crossline_completions_t *p_completion) {
    crossline_color_e cmd_color = CROSSLINE_FGCOLOR_YELLOW |
                                  CROSSLINE_FGCOLOR_BRIGHT |
                                  CROSSLINE_BGCOLOR_DEFAULT;
    crossline_color_e help_color = CROSSLINE_COLOR_DEFAULT;
    for (unsigned i = 0; output_modules_list[i]; i++) {
        if (!strncasecmp(output_modules_list[i]->name, cmd, strlen(cmd))) {
            crossline_completion_add_color(
                p_completion, output_modules_list[i]->name, cmd_color,
                output_modules_list[i]->short_desc
                    ? output_modules_list[i]->short_desc
                    : output_modules_list[i]->desc,
                help_color);
        }
    }
}

static void CPL_generate_module(const char              *cmd,
                                crossline_completions_t *p_completion) {
    crossline_color_e cmd_color = CROSSLINE_FGCOLOR_YELLOW |
                                  CROSSLINE_FGCOLOR_BRIGHT |
                                  CROSSLINE_BGCOLOR_DEFAULT;
    crossline_color_e help_color = CROSSLINE_COLOR_DEFAULT;
    for (unsigned i = 0; generate_modules_list[i]; i++) {
        if (!strncasecmp(generate_modules_list[i]->name, cmd, strlen(cmd))) {
            crossline_completion_add_color(
                p_completion, generate_modules_list[i]->name, cmd_color,
                generate_modules_list[i]->short_desc
                    ? generate_modules_list[i]->short_desc
                    : generate_modules_list[i]->desc,
                help_color);
        }
    }
}

static void CPL_global_conf(const char              *cmd,
                            crossline_completions_t *p_completion) {
    char              help_buf[2048];
    size_t            help_mas  = sizeof(help_buf);
    crossline_color_e cmd_color = CROSSLINE_FGCOLOR_YELLOW |
                                  CROSSLINE_FGCOLOR_BRIGHT |
                                  CROSSLINE_BGCOLOR_DEFAULT;
    crossline_color_e help_color = CROSSLINE_COLOR_DEFAULT;

    for (unsigned i = 0; config_parameters[i].name; i++) {
        bool     matched      = false;
        bool     name_matched = false;
        unsigned j;

        if (!config_parameters[i].help_text) {
            continue;
        }

        if (!strncasecmp(config_parameters[i].name, cmd, strlen(cmd))) {
            matched      = true;
            name_matched = true;
        } else {
            for (j = 0; config_parameters[i].alt_names[j]; j++) {
                if (!strncasecmp(config_parameters[i].alt_names[j], cmd,
                                 strlen(cmd))) {
                    matched = true;
                    break;
                }
            }
        }

        if (matched) {
            int count = 0;

            if (!name_matched) {
                count += snprintf(&help_buf[count], help_mas - count,
                                  "alias: %s", config_parameters[i].name);
            }

            for (unsigned k = 0; config_parameters[i].alt_names[k]; k++) {

                if (!name_matched && j == k)
                    continue;

                /*first printed param in help */
                if (count == 0) {
                    count += snprintf(&help_buf[count], help_mas - count,
                                      "alias: %s",
                                      config_parameters[i].alt_names[k]);
                } else {
                    count +=
                        snprintf(&help_buf[count], help_mas - count, ", %s",
                                 config_parameters[i].alt_names[k]);
                }

                if (count <= 0)
                    break;
            }

            // if (count > 0) {
            //     count += snprintf(&alias_buf[count], alias_max - count, ".");
            // }
            snprintf(&help_buf[count], help_mas - count, "\n    %s\n",
                     config_parameters[i].short_hint
                         ? config_parameters[i].short_hint
                         : config_parameters[i].help_text);

            /**
             * print alias info as help text
             */
            if (name_matched) {
                crossline_completion_add_color(p_completion,
                                               config_parameters[i].name,
                                               cmd_color, help_buf, help_color);
            } else {
                crossline_completion_add_color(
                    p_completion, config_parameters[i].alt_names[j], cmd_color,
                    help_buf, help_color);
            }
        }
    }
}

static const XPrefix config_prefix[] = {
    {PRE_SET_PARAM, HDL_set, CPL_global_conf},
    {PRE_HELP_PARAM, HDL_help_param, CPL_global_conf},
    {PRE_HELP_SCAN, HDL_help_scan, CPL_scan_module},
    {PRE_HELP_PROBE, HDL_help_probe, CPL_probe_module},
    {PRE_HELP_OUT, HDL_help_out, CPL_output_module},
    {PRE_HELP_GEN, HDL_help_gen, CPL_generate_module},
    {PRE_SEARCH_PARAM, HDL_search_param, NULL},
    {PRE_SEARCH_MODULE, HDL_search_module, NULL},

    {0}};

static void _completion_hook(const char              *cmd,
                             crossline_completions_t *p_completion) {
    unsigned i;
    size_t   len;
    bool     cmd_matched    = false;
    bool     prefix_matched = false;

    crossline_color_e cmd_color = CROSSLINE_FGCOLOR_YELLOW |
                                  CROSSLINE_FGCOLOR_BRIGHT |
                                  CROSSLINE_BGCOLOR_DEFAULT;
    crossline_color_e help_color =
        CROSSLINE_FGCOLOR_WHITE | CROSSLINE_BGCOLOR_DEFAULT;

    /**
     * Command
     */
    for (i = 0; config_cmd[i].cmd; i++) {
        len = strlen(cmd);
        if (!strncasecmp(config_cmd[i].cmd, cmd, len)) {
            cmd_matched = true;
            crossline_completion_add_color(p_completion, config_cmd[i].cmd,
                                           cmd_color, config_cmd[i].hint,
                                           help_color);
        }
    }

    if (cmd_matched)
        return;

    /**
     * Prefix
     */
    for (i = 0; config_prefix[i].prefix; i++) {
        len = strlen(config_prefix[i].prefix);
        if (!strncasecmp(config_prefix[i].prefix, cmd, len)) {
            prefix_matched = true;
            break;
        }
    }

    if (prefix_matched && config_prefix[i].completion) {
        config_prefix[i].completion(cmd + len + 1, p_completion);
    }
}

static const char ascii_banner[] =
    "db    db d888888b  .d8b.  d888888b d88888b \n"
    "`8b  d8' `~~88~~' d8' `8b `~~88~~' 88'     \n"
    " `8bd8'     88    88ooo88    88    88ooooo \n"
    " .dPYb.     88    88~~~88    88    88~~~~~ \n"
    ".8P  Y8.    88    88   88    88    88.     \n"
    "YP    YP    YP    YP   YP    YP    Y88888P \n";

void xcmd_interactive_readline(XConf *xconf) {
    printf("\n");
    xprint_with_head(ascii_banner, 15, 80);
    printf("\n");
    xprint("Welcome to " XTATE_NAME_TITLE_CASE "!", 2, 80);
    printf("\n");
    xprint(XTATE_DESCRIPTION, 4, 80);
    printf("\n");
    printf("\n");

    size_t prefix_len;
    size_t line_len;
    ActRes act_res;
    char  *line = MALLOC(READLINE_SIZE * sizeof(char));

    crossline_completion_register(_completion_hook);
    crossline_prompt_color_set(CROSSLINE_FGCOLOR_BRIGHT |
                               CROSSLINE_FGCOLOR_CYAN |
                               CROSSLINE_BGCOLOR_DEFAULT);

    while (NULL !=
           crossline_readline(XTATE_NAME_ALL_CAPS "> ", line, READLINE_SIZE)) {
        unsigned i;
        bool     cmd_matched    = false;
        bool     prefix_matched = false;

        safe_trim(line, READLINE_SIZE);
        if (line[0] == 0)
            continue;

        line_len = strlen(line);

        /**
         * Command
         */
        for (i = 0; config_cmd[i].cmd; i++) {
            if (!strcasecmp(config_cmd[i].cmd, line)) {
                cmd_matched = true;
                break;
            }
        }

        if (cmd_matched) {
            act_res = config_cmd[i].action(xconf);
            if (act_res == ActRes_Next)
                continue;
            else if (act_res == ActRes_Finish)
                break;
        }

        /**
         * Prefix Command
         */
        for (i = 0; config_prefix[i].prefix; i++) {
            prefix_len = strlen(config_prefix[i].prefix);
            /*like `prefix-cmd subcmd`*/
            if (!strncasecmp(config_prefix[i].prefix, line, prefix_len)) {
                prefix_matched = true;
                break;
            }
        }

        if (prefix_matched) {
            if (line_len > prefix_len + 1 && line[prefix_len] == ' ') {
                config_prefix[i].handle(xconf, line + prefix_len + 1,
                                        READLINE_SIZE - prefix_len - 1);
                continue;
            } else if (line_len == prefix_len) {
                LOG(LEVEL_ERROR,
                    "(" XTATE_NAME
                    ") need to specify a param for the command.\n");
                continue;
            }
        }

        LOG(LEVEL_ERROR, "(" XTATE_NAME ") unknown input, use <TAB> to get.\n");
    }

    FREE(line);
}
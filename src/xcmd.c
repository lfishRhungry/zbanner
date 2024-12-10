#include "xcmd.h"

#include "version.h"
#include "crossline/crossline.h"
#include "target/target-cookie.h"

#include "util-out/logger.h"
#include "util-data/safe-string.h"
#include "util-data/fine-malloc.h"
#include "xconf.h"
#include <openssl/ec.h>
#include <stdint.h>
#include <stdio.h>

#define READLINE_SIZE 65535

extern ConfParam config_parameters[];

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
    printf("This is the help\n");
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

static ActRes ACT_prefix(void *conf) { return ActRes_Prefix; }

#define PRE_SET_PARAM    "set"
#define PRE_HELP_PARAM   "help-param"
#define PRE_SEARCH_PARAM "search-param"

static const XCmd config_cmd[] = {
    {"run", "Execute " XTATE_NAME " with configured parmas.", ACT_run},
    {"exit", "Exit the program directly.", ACT_exit},
    {"clear", "Refresh configuration to default except `seed`.", ACT_clear},
    {"version", "Print version info of " XTATE_NAME_TITLE_CASE, ACT_version},
    {"echo", "Print current configuration of " XTATE_NAME_TITLE_CASE, ACT_echo},
    {"echo-all", "Print all configuration of " XTATE_NAME_TITLE_CASE,
     ACT_echo_all},
    {"help", "Print help information for interactive command mode.", ACT_help},
    {"update-seed", "Update the global seed to a new rand number.",
     ACT_update_seed},
    {PRE_SET_PARAM,
     "Set a global param of " XTATE_NAME_TITLE_CASE " like `set key = value`.",
     ACT_prefix},
    {PRE_HELP_PARAM, "Print help of a specified global param.", ACT_prefix},
    {PRE_SEARCH_PARAM,
     "Fuzzy search global params of " XTATE_NAME_TITLE_CASE ".", ACT_prefix},

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

static void HDL_search_param(void *conf, char *subcmd, size_t len) {
    xconf_search_param(subcmd);
}

static void CPL_global_conf(const char              *cmd,
                            crossline_completions_t *p_completion) {
    char   alias_buf[256];
    size_t alias_max = sizeof(alias_buf);

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
            for (unsigned k = 0; config_parameters[i].alt_names[k]; k++) {

                if (!name_matched && j == k)
                    continue;

                /*first printed param in help */
                if (count == 0) {
                    count += snprintf(&alias_buf[count], alias_max - count,
                                      "alias: %s",
                                      config_parameters[i].alt_names[k]);
                } else {
                    count +=
                        snprintf(&alias_buf[count], alias_max - count, ", %s",
                                 config_parameters[i].alt_names[k]);
                }

                if (count <= 0)
                    break;
            }

            /**
             * print alias info as help text
             */
            if (name_matched) {
                crossline_completion_add(p_completion,
                                         config_parameters[i].name, alias_buf);
            } else {
                crossline_completion_add(
                    p_completion, config_parameters[i].alt_names[j], alias_buf);
            }
        }
    }
}

static const XPrefix config_prefix[] = {
    {PRE_SET_PARAM, HDL_set, CPL_global_conf},
    {PRE_HELP_PARAM, HDL_help_param, CPL_global_conf},
    {PRE_SEARCH_PARAM, HDL_search_param, NULL},

    {0}};

static void _completion_hook(const char              *cmd,
                             crossline_completions_t *p_completion) {
    unsigned i;
    size_t   len;
    bool     cmd_matched    = false;
    bool     prefix_matched = false;

    /**
     * Command
     */
    for (i = 0; config_cmd[i].cmd; i++) {
        len = strlen(cmd);
        if (!strncasecmp(config_cmd[i].cmd, cmd, len)) {
            cmd_matched = true;
            crossline_completion_add(p_completion, config_cmd[i].cmd,
                                     config_cmd[i].hint);
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

void xcmd_interactive_readline(XConf *xconf) {
    size_t prefix_len;
    ActRes act_res;
    char  *line = MALLOC(READLINE_SIZE * sizeof(char));

    crossline_completion_register(_completion_hook);
    crossline_prompt_color_set(CROSSLINE_FGCOLOR_BRIGHT |
                               CROSSLINE_FGCOLOR_CYAN);

    while (NULL !=
           crossline_readline(XTATE_NAME_ALL_CAPS "> ", line, READLINE_SIZE)) {
        unsigned i;
        bool     cmd_matched    = false;
        bool     prefix_matched = false;

        safe_trim(line, READLINE_SIZE);
        if (line[0] == 0)
            continue;

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
            if (!strncasecmp(config_prefix[i].prefix, line, prefix_len) &&
                strlen(line) > prefix_len + 1 && line[prefix_len] == ' ') {
                prefix_matched = true;
                config_prefix[i].handle(xconf, line + prefix_len + 1,
                                        READLINE_SIZE - prefix_len - 1);
            }
        }

        if (prefix_matched)
            continue;

        LOG(LEVEL_ERROR, "(" XTATE_NAME ") invalid input.\n");
    }

    FREE(line);
}
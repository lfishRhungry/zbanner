#ifndef OUTPUT_MODULES_H
#define OUTPUT_MODULES_H

#include <time.h>
#include <ctype.h>
#include <stdio.h>

#include "../util-misc/configer.h"
#include "../util-misc/cross.h"
#include "../massip/massip-addr.h"

#define OUT_RSN_SIZE          30
#define OUT_CLS_SIZE          30
/**
 * Relative with XCONF_DFT_SNAPLEN and XCONF_DFT_MAX_PKT_LEN
 * I don't agree that always report all content that we received, xtate is not
 * a browser or scrapper*/
#define OUT_RPT_SIZE          2048

struct OutputModule;

enum OutputLevel {
    Output_INFO     = 0,
    Output_FAILURE  = 1,
    Output_SUCCESS  = 2,
};

struct OutputItem {
    time_t                       timestamp;
    enum OutputLevel             level;
    ipaddress                    ip_them;
    unsigned                     port_them;                        /*no outputting if zero*/
    ipaddress                    ip_me;
    unsigned                     port_me;                          /*no outputting if zero*/
    char                         reason[OUT_RSN_SIZE];             /*no outputting if start with zero*/
    char                         classification[OUT_CLS_SIZE];     /*no outputting if start with zero*/
    char                         report[OUT_RPT_SIZE];             /*no outputting if start with zero*/
    unsigned                     no_output:1;
};

struct Output {
    struct OutputModule         *output_module;
    char                        *output_args;
    char                         output_filename[256];
    FILE                        *output_file;
    uint64_t                     total_successed;
    uint64_t                     total_failed;
    uint64_t                     total_info;
    void                        *succ_mutex;
    void                        *fail_mutex;
    void                        *info_mutex;
    void                        *module_mutex;
    void                        *stdout_mutex;
    unsigned                     is_append:1;
    unsigned                     is_interactive:1;
    unsigned                     is_show_failed:1;
    unsigned                     is_show_info:1;
};

/**
 * Do init for outputing
*/
typedef bool
(*output_modules_init)(const struct Output *out);

/**
 * Output one result
*/
typedef void
(*output_modules_result)(const struct Output *out, const struct OutputItem *item);

/**
 * Do close for outputing
*/
typedef void
(*output_modules_close)(const struct Output *out);

struct OutputModule {
    const char                               *name;
    const char                               *desc;
    unsigned                                  need_file:1;
    struct ConfigParam                       *params; 
    output_modules_init                       init_cb;
    output_modules_result                     result_cb;
    output_modules_close                      close_cb;
};

/*prepare for outputing results*/
bool
output_init(struct Output *output);

void
output_result(
    const struct Output *output,
    const struct OutputItem *item);

/*destroy resources of output*/
void
output_close(struct Output *output);

struct OutputModule *
get_output_module_by_name(const char *name);

void list_all_output_modules();

/************************************************************************
Some useful implemented interfaces
************************************************************************/

bool output_init_nothing(const struct Output *output);

void output_result_nothing(const struct Output *out, const struct OutputItem *item);

void output_close_nothing(const struct Output *out);

#endif
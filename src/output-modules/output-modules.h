#ifndef OUTPUT_MODULES_H
#define OUTPUT_MODULES_H

#include <time.h>
#include <ctype.h>
#include <stdio.h>

#include "../util-data/data-chain.h"
#include "../util-misc/configer.h"
#include "../util-misc/cross.h"
#include "../massip/massip.h"
#include "../massip/massip-addr.h"

#define OUTPUT_RSN_SIZE          30
#define OUTPUT_CLS_SIZE          30

struct OutputModule;

enum OutputLevel {
    Output_INFO     = 0,
    Output_FAILURE  = 1,
    Output_SUCCESS  = 2,
};

struct OutputItem {
    /**This timestamp can be set in diff meanings by yourself like time of receiving
     * packet or time of result generated.
     * It will be set in output func by global time if hasn't be set by any module.*/
    time_t                       timestamp;
    /**Type of result item itself. INFO and FAILURE are not to be output by default
     * unless using `--show fail` or `--show info`.*/
    enum OutputLevel             level;
    /**IP proto number to mention whether it is TCP, UDP, etc.*/
    unsigned                     ip_proto;
    /**IP of target*/
    ipaddress                    ip_them;
    /**Port of target.
     * It won't be outputting in stdout and text if start with zero, suggest to set it*/
    unsigned                     port_them;
    /**IP of target.
     * Our ip can be random when multi src ip set.
     * It won't be showed in default stdout and text outputing.*/
    ipaddress                    ip_me;
    /**IP of target.
     * Our ip can be random when multi src ip set.
     * It won't be showed in default stdout and text outputing.*/
    unsigned                     port_me;
    /**Type of this result. It is recommended to set a value.
     * No double or single quotes in it for output format.
     * It won't be outputting in stdout and text if start with zero, suggest to set it*/
    char                         classification[OUTPUT_CLS_SIZE];
    /**Why we set this result to that classification.
     * No double or single quotes in it for output format.
     * It won't be outputting in stdout and text if start with zero, suggest to set it*/
    char                         reason[OUTPUT_RSN_SIZE];
    /**Other thing need to be report. It's a dynamic and user-defined field in
     * key-value format. You can set data link is_number to mention it is a num type.
     * No double or single quotes in it for output format.
     * It won't be outputting in stdout and text if start with zero, suggest to set it*/
    struct DataChain             report;
    /**This result item won't be output if it set to true*/
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
    unsigned                     no_show_success:1;
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
(*output_modules_result)(struct OutputItem *item);

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

const char *
output_level_to_string(enum OutputLevel level);

/*prepare for outputing results*/
bool
output_init(struct Output *out);

/**
 * output a result within item and release datachain(report) in it.
*/
void
output_result(const struct Output *out, struct OutputItem *item);

/*destroy resources of output*/
void
output_close(struct Output *out);

struct OutputModule *
get_output_module_by_name(const char *name);

void list_all_output_modules();

/************************************************************************
Some useful implemented interfaces
************************************************************************/

bool output_init_nothing(const struct Output *out);

void output_result_nothing(struct OutputItem *item);

void output_close_nothing(const struct Output *out);

#endif
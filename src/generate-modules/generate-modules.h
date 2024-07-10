#ifndef GENERATE_MODULES_H
#define GENERATE_MODULES_H

#include <time.h>
#include <ctype.h>
#include <stdio.h>

#include "../util-data/data-chain.h"
#include "../util-misc/configer.h"
#include "../util-misc/cross.h"
#include "../target/target.h"
#include "../target/target-ip.h"
#include "../target/target-addr.h"

typedef struct XtateConf XConf;
struct source_t;

/**
 * !Must be implemented.
 * !Happens in Main Thread.
 * 
 * @param xconf main conf of xtate
 * @return FALSE to exit process if init failed
 */
typedef bool
(*generate_modules_init)(const XConf *xconf);

/**
 * !Must be implemented.
 * !Must be thread safe for itself.
 * !Happens in Tx Threads & main Thread.
 * 
 * Test if has more target for this index.
 * It's the condition of stoping tx threads.
 * 
 * @param tx_index index of tx thread
 * @param index index of target traveling
 * @return FALSE to exit process if init failed
 */
typedef bool
(*generate_modules_hasmore)(unsigned tx_index, uint64_t index);

/**
 * !Must be implemented.
 * !Must be thread safe for itself.
 * !Happens in Tx Threads.
 * 
 * generate a target for this index.
 * 
 * @param tx_index index of tx thread
 * @param index index of target traveling
 * @param repeat current repeat count
 * @param src info of source ip and port setting
 * @return FALSE to exit process if init failed
 */
typedef Target
(*generate_modules_generate)(unsigned tx_index, uint64_t index,
    uint64_t repeat, struct source_t *src);

/**
 * !Must be implemented.
 * !Happens in Main Thread.
 * 
 */
typedef void
(*generate_modules_close)();

typedef struct GenerateModule {
    const char                               *name;
    const char                               *desc;
    ConfParam                                *params; 
    /**
     * could be dynamicly updated after inited.
     * could be zero if don't know.
     */
    uint64_t                                  target_range;
    /**
     * could be dynamicly updated after inited.
     */
    uint64_t                                  count_ips;
    /**
     * could be dynamicly updated after inited.
     */
    uint64_t                                  count_ports;
    /**
     * could be dynamicly updated after inited.
     */
    bool                                      has_ipv4_targets;
    /**
     * could be dynamicly updated after inited.
     */
    bool                                      has_ipv6_targets;

    generate_modules_init                     init_cb;
    generate_modules_hasmore                  hasmore_cb;
    generate_modules_generate                 generate_cb;
    generate_modules_close                    close_cb;
} Generator;

Generator *get_generate_module_by_name(const char *name);

void list_all_generate_modules();

void help_generate_module(Generator *module);

/*implemented `generate_modules_init`*/
bool
generate_init_nothing(const XConf *xconf);

/*implemented `generate_modules_close`*/
void
generate_close_nothing(const XConf *xconf);


#endif
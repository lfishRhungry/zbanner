/**
 * GenerateModule or Generator is an abstraction for scan targets generation.
 * It makes target generation extensible and flexible. I expect that users can
 * design their own target generation algorithms, or method like gererating
 * from database or files, even design it with OutputModule together. Unlike
 * ProbeModule or ScanModule, Gererator is a low-level module. It's a big
 * challenge to write one. So Xtate provide usable functions in possible. For
 * example, getting address set from command line or file will be automaticlly
 * finished.
 *
 * NOTE: It's better to understand the process of Tx Thread before writing a
 * Generator.
 */
#ifndef GENERATE_MODULES_H
#define GENERATE_MODULES_H

#include <time.h>
#include <ctype.h>
#include <stdio.h>

#include "../util-data/data-chain.h"
#include "../util-misc/configer.h"
#include "../util-misc/cross.h"
#include "../target/target.h"
#include "../target/target-set.h"
#include "../target/target-ipaddress.h"

typedef struct XtateConf XConf;

struct source_t;

/**
 * !Must be implemented.
 * !Happens in Main Thread.
 *
 * @param xconf main conf of xtate
 * @param count_targets We use target and endpoint for generalizing. Not all
 * modules would using host. A target can be an IP, URL or any others. However,
 * a target is a host in most cases. This is for main thread to print some
 * running info. Do not care it or set it to zero if don't know the value from
 * beginning.
 * @param count_endpoints We use endpoint for generalizing. Not all modules
 * would using port. An endpoint can be a port, TTL, IP protocol, sub-directory
 * or any others. However, an endpoint is a port in most cases. This is for main
 * thread to print some running info. Do not care it or set it to zero if don't
 * know the value from beginning.
 * @param init_ipv4 This is for main thread to init adapter for ipv4 optionally.
 * Do not care it if don't know the value from beginning because it could be
 * setted manually by global conf.
 * @param init_ipv6 This is for main thread to init adapter for ipv6 optionally.
 * Do not care it if don't know the value from beginning because it could be
 * setted manually by global conf.
 * @return FALSE to exit process if init failed
 */
typedef bool (*generate_modules_init)(const XConf *xconf,
                                      uint64_t    *count_targets,
                                      uint64_t    *count_endpoints,
                                      bool *init_ipv4, bool *init_ipv6);

/**
 * !Must be implemented.
 * !Must be thread safe for itself.
 * !Happens in Tx Threads & main Thread.
 *
 * Test if generator has more target for this index on tx_index thread. It's
 * also the condition to stop tx threads. Tx Thread will jump out send loop if
 * generator has no more target. Main Thread will stop all Tx Threads if
 * generatror has no more target for every Tx Threads.
 * NOTE:Every time before calling `generate` func, `hasmore` func will be called
 * at least once with a `true` result.
 *
 * @param tx_index index of tx thread
 * @param index index of target traveling
 * @return FALSE to exit process if init failed
 */
typedef bool (*generate_modules_hasmore)(unsigned tx_index, uint64_t index);

/**
 * !Must be implemented.
 * !Must be thread safe for itself.
 * !Happens in Tx Threads.
 *
 * generate a target for this index on tx_index thread.
 *
 * @param tx_index index of tx thread
 * @param index index of target traveling
 * @param repeat current repeat count
 * @param src info of source ip and port setting
 * @return FALSE to exit process if init failed
 */
typedef Target (*generate_modules_generate)(unsigned tx_index, uint64_t index,
                                            uint64_t         repeat,
                                            struct source_t *src);

/**
 * !Must be implemented.
 * !Happens in Main Thread.
 *
 */
typedef void (*generate_modules_close)();

typedef struct GenerateModule {
    const char *name;
    const char *short_desc; /*an optional short description*/
    const char *desc;
    ConfParam  *params;

    generate_modules_init     init_cb;
    generate_modules_hasmore  hasmore_cb;
    generate_modules_generate generate_cb;
    generate_modules_close    close_cb;
} Generator;

Generator *get_generate_module_by_name(const char *name);

void list_all_generate_modules();

void help_generate_module(Generator *module);

/*implemented `generate_modules_init`*/
bool generate_init_nothing(const XConf *xconf, uint64_t *count_targets,
                           uint64_t *count_endpoints, bool *init_ipv4,
                           bool *init_ipv6);

/*implemented `generate_modules_close`*/
void generate_close_nothing(const XConf *xconf);

#endif
/**
 * This was originally extracted from masscan's parm config workflow(a little
 * messy...). I updated  and abstracted it into a useful parm configer tool.
 * Some features:
 * - Single or double dash for parm name is valid: `-name` or `--name`
 * - Any dash within parm name is valid: `-na-me` or `--nam-e`
 * - Args can be carried in multiple ways: `-name arg`, `-name:arg`, `-name=arg`
 * - Parm name can carry sub str or int: `-name[2] arg` or `-name[hello] arg`,
 *   this should be further parsed by parse_opt_xxx funcs.
 *
 * Modified and Created by sharkocha 2024
 */
#ifndef CONFIGER_H
#define CONFIGER_H

#include <stdint.h>

#include "cross.h"
#include "../target/target-addr.h"

typedef enum Config_RES {
    Conf_OK,
    Conf_ERR,
} ConfRes;

typedef enum ConfigParam_TYPE {
    Type_ARG  = 0, /*may carry args like `--parm arg` or `--parm=arg`*/
    Type_FLAG = 1, /*only a single flag, even can be --parm=false*/
} ConfType;

/**
 * @param conf where parameters would be set
 * @param name param name
 * @param value param value
 * @return enum ConfigRes or 0 in echo mode.
 */
typedef ConfRes (*CONFIG_SET_PARAM)(void *conf, const char *name,
                                    const char *value);

typedef struct ConfigParam {
    const char      *name;
    CONFIG_SET_PARAM setter;
    ConfType         type;
    const char      *alt_names[8];
    const char      *help_text; /*set NULL if it's not a normal prarameter*/
} ConfParam;

bool is_str_bool(const char *str);
bool is_str_int(const char *value);
bool is_power_of_two(uint64_t x);

uint64_t parse_str_time(const char *value);
uint64_t parse_str_size(const char *value);
int      parse_str_mac(const char *text, macaddress_t *mac);
uint64_t parse_str_int(const char *str);
bool     parse_str_bool(const char *str);

unsigned parse_char_hex(char c);

unsigned parse_opt_int(const char *name);
char    *parse_opt_str(const char *name);

bool is_parm_flag(const ConfParam *cp, const char *name);

bool     EQUALS(const char *lhs, const char *rhs);
bool     EQUALSx(const char *lhs, const char *rhs, size_t rhs_length);
unsigned INDEX_OF(const char *str, char c);

void set_one_parameter(void *conf, ConfParam *cp, const char *name,
                       const char *value);
void set_parameters_from_args(void *conf, ConfParam *cp, int argc, char **argv);
int  set_parameters_from_string(void *conf, ConfParam *cp, char *string);
int  set_parameters_from_substring(void *conf, ConfParam *cp, char *substring);

#endif
#ifndef CONFIGER_H
#define CONFIGER_H

#include <stdint.h>

#include "cross.h"
#include "../target/target-addr.h"

typedef enum Config_RES {
    Conf_OK,
    Conf_WARN,
    Conf_ERR,
} ConfRes;

typedef enum ConfigParam_TYPE {
    Type_NONE = 0,
    Type_BOOL = 1,
    Type_NUM  = 2,
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
    const char      *help_text; /*set NULL if not normal prarameter*/
} ConfParam;

uint64_t parseInt(const char *str);

bool isBoolean(const char *str);

bool parseBoolean(const char *str);

/***************************************************************************
 * Parses the number of seconds (for rotating files mostly). We do a little
 * more than just parse an integer. We support strings like:
 *
 * hourly
 * daily
 * Week
 * 5days
 * 10-months
 * 3600
 ***************************************************************************/
uint64_t parseTime(const char *value);

/***************************************************************************
 * Parses a size integer, which can be suffixed with "tera", "giga",
 * "mega", and "kilo". These numbers are in units of 1024 so suck it.
 ***************************************************************************/
uint64_t parseSize(const char *value);

unsigned parseHexChar(char c);

int parseMacAddress(const char *text, macaddress_t *mac);

unsigned parseOptionInt(const char *name);

char *parseOptionStr(const char *name);

/***************************************************************************
 * Tests if the named parameter on the command-line. We do a little
 * more than a straight string compare, because I get confused
 * whether parameter have punctuation. Is it "--excludefile" or
 * "--exclude-file"? I don't know if it's got that dash. Screw it,
 * I'll just make the code so it don't care.
 ***************************************************************************/
bool EQUALS(const char *lhs, const char *rhs);

bool EQUALSx(const char *lhs, const char *rhs, size_t rhs_length);

unsigned INDEX_OF(const char *str, char c);

bool is_integer(const char *value);

bool is_numable(const ConfParam *cp, const char *name);

bool is_power_of_two(uint64_t x);

/***************************************************************************
 * Command-line parsing code assumes every --parm is followed by a value.
 * This is a list of the parameters that don't follow the default.
 ***************************************************************************/
bool is_singleton(const ConfParam *cp, const char *name);

/*
 * Go through configured list of parameters
 */
void set_one_parameter(void *conf, ConfParam *cp, const char *name,
                       const char *value);

/**
 * argc and argv do not contain process file name
 */
void set_parameters_from_args(void *conf, ConfParam *cp, int argc, char **argv);

/**
 * Parse string and set parameters
 * It can handle quotes(ignore single quotes)
 * @param conf config to set params
 * @param cp params
 * @param string whole string contains all params
 * @return 0 if success
 */
int set_parameters_from_string(void *conf, ConfParam *cp, char *string);

/**
 * Parse string and set parameters
 * It can handle single quotes(ignore quotes)
 * @param conf config to set params
 * @param cp params
 * @param substring whole string contains all params
 * @return 0 if success
 */
int set_parameters_from_substring(void *conf, ConfParam *cp, char *substring);

#endif
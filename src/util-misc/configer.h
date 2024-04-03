#ifndef CONFIGER_H
#define CONFIGER_H

#include <stdint.h>

#include "cross.h"
#include "../massip/massip-addr.h"

enum Config_Res {
    CONF_OK,
    CONF_WARN,
    CONF_ERR
};

enum Config_Flag {
    F_NONE      = 0,
    F_BOOL      = 1,
    F_NUMABLE   = 2
};

/**
 * @param conf where parameters would be set
 * @param name param name
 * @param value param value
 * @return (CONF_OK, CONF_WARN, CONF_ERR) or 0 in echo mode.
*/
typedef enum Config_Res (*SET_PARAMETER)(void *conf, const char *name, const char *value);


struct ConfigParam {
    const char            *name;
    SET_PARAMETER          set;
    enum Config_Flag       flags;
    const char            *alts[8];
    const char            *helps; /*set NULL if not normal prarameter*/
};

uint64_t
parseInt(const char *str);

bool
isBoolean(const char *str);

bool
parseBoolean(const char *str);

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
uint64_t
parseTime(const char *value);

/***************************************************************************
 * Parses a size integer, which can be suffixed with "tera", "giga", 
 * "mega", and "kilo". These numbers are in units of 1024 so suck it.
 ***************************************************************************/
uint64_t
parseSize(const char *value);

unsigned
hexval(char c);

int
parse_mac_address(const char *text, macaddress_t *mac);

bool
is_power_of_two(uint64_t x);

/***************************************************************************
 * Tests if the named parameter on the command-line. We do a little
 * more than a straight string compare, because I get confused
 * whether parameter have punctuation. Is it "--excludefile" or
 * "--exclude-file"? I don't know if it's got that dash. Screw it,
 * I'll just make the code so it don't care.
 ***************************************************************************/
bool
EQUALS(const char *lhs, const char *rhs);

bool
EQUALSx(const char *lhs, const char *rhs, size_t rhs_length);

unsigned
INDEX_OF(const char *str, char c);

unsigned
ARRAY(const char *rhs);

bool
isInteger(const char *value);

bool
is_numable(const struct ConfigParam *cp, const char *name);

/***************************************************************************
 * Command-line parsing code assumes every --parm is followed by a value.
 * This is a list of the parameters that don't follow the default.
 ***************************************************************************/
bool
is_singleton(const struct ConfigParam *cp, const char *name);

/*
    * Go through configured list of parameters
*/
void
set_one_parameter(void *conf, struct ConfigParam *cp,
    const char *name, const char *value);

/**
 * argc and argv do not contain process file name
*/
void
set_parameters_from_args(void *conf, struct ConfigParam *cp,
    int argc, char **argv);

/**
 * Parse string and set parameters
 * It can handle quotes(ignore single quotes)
 * @param conf config to set params
 * @param cp params
 * @param string whole string contains all params
 * @return 0 if success
*/
int
set_parameters_from_string(void *conf, struct ConfigParam *cp, char *string);

/**
 * Parse string and set parameters
 * It can handle single quotes(ignore quotes)
 * @param conf config to set params
 * @param cp params
 * @param substring whole string contains all params
 * @return 0 if success
*/
int
set_parameters_from_substring(void *conf, struct ConfigParam *cp, char *substring);

#endif
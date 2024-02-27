#ifndef PARAM_CONFIGER_H
#define PARAM_CONFIGER_H

#include "xconf.h"

#ifndef min
#define min(a,b) ((a)<(b)?(a):(b))
#endif

/**
 * @param conf Xconf
 * @param name param name
 * @param value param value
 * @return (CONF_OK, CONF_WARN, CONF_ERR) or 0 in echo mode.
*/
typedef int (*SET_PARAMETER)(struct Xconf *conf, const char *name, const char *value);

enum {CONF_OK, CONF_WARN, CONF_ERR};

struct ConfigParameter {
    const char *name;
    SET_PARAMETER set;
    unsigned flags;
    const char *alts[6];
    const char *helps; /*set NULL if not normal prarameter*/
};

enum {F_NONE, F_BOOL=1, F_NUMABLE=2};

uint64_t
parseInt(const char *str);

bool
isBoolean(const char *str);

unsigned
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

int
is_power_of_two(uint64_t x);

/***************************************************************************
 * Tests if the named parameter on the command-line. We do a little
 * more than a straight string compare, because I get confused
 * whether parameter have punctuation. Is it "--excludefile" or
 * "--exclude-file"? I don't know if it's got that dash. Screw it,
 * I'll just make the code so it don't care.
 ***************************************************************************/
int
EQUALS(const char *lhs, const char *rhs);

int
EQUALSx(const char *lhs, const char *rhs, size_t rhs_length);

unsigned
INDEX_OF(const char *str, char c);

unsigned
ARRAY(const char *rhs);

int
isInteger(const char *value);

bool
is_numable(const struct ConfigParameter *cp, const char *name);

/***************************************************************************
 * Command-line parsing code assumes every --parm is followed by a value.
 * This is a list of the parameters that don't follow the default.
 ***************************************************************************/
int
is_singleton(const struct ConfigParameter *cp, const char *name);

/*
    * Go through configured list of parameters
*/
void
set_one_parameter(struct Xconf *xconf, struct ConfigParameter *cp,
    const char *name, const char *value);

void
set_parameters_from_args(struct Xconf *xconf, struct ConfigParameter *cp,
    int argc, char **argv);

/**
 * It is for params parsing of submodules
 * @param string whole string contains all params
*/
void
set_parameters_from_string(struct Xconf *xconf, struct ConfigParameter *cp,
    char *string, unsigned str_len);

/***************************************************************************
 * Prints the current configuration to the command-line then exits.
 * Use#1: create a template file of all settable parameters.
 * Use#2: make sure your configuration was interpreted correctly.
 ***************************************************************************/
void
paramters_echo(struct Xconf *xconf, FILE *fp, struct ConfigParameter *cp);

#endif
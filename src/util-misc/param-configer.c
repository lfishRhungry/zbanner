#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "param-configer.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"

uint64_t
parseInt(const char *str)
{
    uint64_t result = 0;

    while (*str && isdigit(*str & 0xFF)) {
        result = result * 10 + (*str - '0');
        str++;
    }
    return result;
}

/**
 * a stricter function for determining if something is boolean.
 */
bool
isBoolean(const char *str) {
    size_t length = str?strlen(str):0;

    if (length == 0)
        return false;

    /* "0" or "1" is boolean */
    if (isdigit(str[0])) {
        if (strtoul(str,0,0) == 0)
            return true;
        else if (strtoul(str,0,0) == 1)
            return true;
        else
            return false;
    }

    switch (str[0]) {
        case 'e':
        case 'E':
            if (memcasecmp("enable", str, length)==0)
                return true;
            if (memcasecmp("enabled", str, length)==0)
                return true;
            return false;
        case 'd':
        case 'D':
            if (memcasecmp("disable", str, length)==0)
                return true;
            if (memcasecmp("disabled", str, length)==0)
                return true;
            return false;

        case 't':
        case 'T':
            if (memcasecmp("true", str, length)==0)
                return true;
            return false;
        case 'f':
        case 'F':
            if (memcasecmp("false", str, length)==0)
                return true;
            return false;

        case 'o':
        case 'O':
            if (memcasecmp("on", str, length)==0)
                return true;
            if (memcasecmp("off", str, length)==0)
                return true;
            return false;
        case 'Y':
        case 'y':
            if (memcasecmp("yes", str, length)==0)
                return true;
            return false;
        case 'n':
        case 'N':
            if (memcasecmp("no", str, length)==0)
                return true;
            return false;
        default:
            return false;
    }
}

unsigned
parseBoolean(const char *str)
{
    if (str == NULL || str[0] == 0)
        return 1;
    if (isdigit(str[0])) {
        if (strtoul(str,0,0) == 0)
            return 0;
        else
            return 1;
    }
    switch (str[0]) {
    case 'e': /* enable */
    case 'E':
        return 1;
    case 'd': /* disable */
    case 'D':
        return 0;

    case 't': /* true */
    case 'T':
        return 1;
    case 'f': /* false */
    case 'F':
        return 0;

    case 'o': /* on or off */
    case 'O':
        if (str[1] == 'f' || str[1] == 'F')
            return 0;
        else
            return 1;
        break;

    case 'Y': /* yes */
    case 'y':
        return 1;
    case 'n': /* no */
    case 'N':
        return 0;
    }
    return 1;
}

uint64_t
parseTime(const char *value)
{
    uint64_t num = 0;
    unsigned is_negative = 0;

    while (*value == '-') {
        is_negative = 1;
        value++;
    }

    while (isdigit(value[0]&0xFF)) {
        num = num*10 + (value[0] - '0');
        value++;
    }
    while (ispunct(value[0]) || isspace(value[0]))
        value++;

    if (isalpha(value[0]) && num == 0)
        num = 1;

    if (value[0] == '\0')
        return num;

    switch (tolower(value[0])) {
    case 's':
        num *= 1;
        break;
    case 'm':
        num *= 60;
        break;
    case 'h':
        num *= 60*60;
        break;
    case 'd':
        num *= 24*60*60;
        break;
    case 'w':
        num *= 24*60*60*7;
        break;
    default:
        fprintf(stderr, "--rotate-offset: unknown character\n");
        exit(1);
    }
    if (num >= 24*60*60) {
        fprintf(stderr, "--rotate-offset: value is greater than 1 day\n");
        exit(1);
    }
    if (is_negative)
        num = 24*60*60 - num;

    return num;
}

uint64_t
parseSize(const char *value)
{
    uint64_t num = 0;

    while (isdigit(value[0]&0xFF)) {
        num = num*10 + (value[0] - '0');
        value++;
    }
    while (ispunct(value[0]) || isspace(value[0]))
        value++;

    if (isalpha(value[0]) && num == 0)
        num = 1;

    if (value[0] == '\0')
        return num;

    switch (tolower(value[0])) {
    case 'k': /* kilobyte */
        num *= 1024ULL;
        break;
    case 'm': /* megabyte */
        num *= 1024ULL * 1024ULL;
        break;
    case 'g': /* gigabyte */
        num *= 1024ULL * 1024ULL * 1024ULL;
        break;
    case 't': /* terabyte, 'cause we roll that way */
        num *=  1024ULL * 1024ULL * 1024ULL * 1024ULL;
        break;
    case 'p': /* petabyte, 'cause we are awesome */
        num *=  1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
        break;
    case 'e': /* exabyte, now that's just silly */
        num *=  1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
        break;
    default:
        fprintf(stderr, "--rotate-size: unknown character\n");
        exit(1);
    }
    return num;
}

unsigned
hexval(char c)
{
    if ('0' <= c && c <= '9')
        return (unsigned)(c - '0');
    if ('a' <= c && c <= 'f')
        return (unsigned)(c - 'a' + 10);
    if ('A' <= c && c <= 'F')
        return (unsigned)(c - 'A' + 10);
    return 0xFF;
}

int
parse_mac_address(const char *text, macaddress_t *mac)
{
    unsigned i;

    for (i=0; i<6; i++) {
        unsigned x;
        char c;

        while (isspace(*text & 0xFF) && ispunct(*text & 0xFF))
            text++;

        c = *text;
        if (!isxdigit(c&0xFF))
            return -1;
        x = hexval(c)<<4;
        text++;

        c = *text;
        if (!isxdigit(c&0xFF))
            return -1;
        x |= hexval(c);
        text++;

        mac->addr[i] = (unsigned char)x;

        if (ispunct(*text & 0xFF))
            text++;
    }

    return 0;
}

int
is_power_of_two(uint64_t x)
{
    while ((x&1) == 0)
        x >>= 1;
    return x == 1;
}

int
EQUALS(const char *lhs, const char *rhs)
{
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return 1; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return 0;
        if (*lhs == '\0')
            return 1;
        lhs++;
        rhs++;
    }
}

int
EQUALSx(const char *lhs, const char *rhs, size_t rhs_length)
{
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return 1; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return 0;
        if (*lhs == '\0')
            return 1;
        lhs++;
        rhs++;
        if (--rhs_length == 0)
            return 1;
    }
}

unsigned
INDEX_OF(const char *str, char c)
{
    unsigned i;
    for (i=0; str[i] && str[i] != c; i++)
        ;
    return i;
}

unsigned
ARRAY(const char *rhs)
{
    const char *p = strchr(rhs, '[');
    if (p == NULL)
        return 0;
    else
        p++;
    return (unsigned)parseInt(p);
}

int
isInteger(const char *value)
{
    size_t i;
    
    if (value == NULL)
        return 0;
    
    for (i=0; value[i]; i++)
        if (!isdigit(value[i]&0xFF))
            return 0;
    return 1;
}

bool
is_numable(const struct ConfigParameter *cp, const char *name)
{
    size_t i;

    for (i=0; cp[i].name; i++) {
        if (EQUALS(cp[i].name, name)) {
            return (cp[i].flags & F_NUMABLE) == F_NUMABLE;
        } else {
            size_t j;
            for (j=0; cp[i].alts[j]; j++) {
                if (EQUALS(cp[i].alts[j], name)) {
                    return (cp[i].flags & F_NUMABLE) == F_NUMABLE;
                }
            }
        }
    }
    return false;
}

/***************************************************************************
 * Command-line parsing code assumes every --parm is followed by a value.
 * This is a list of the parameters that don't follow the default.
 ***************************************************************************/
int
is_singleton(const struct ConfigParameter *cp, const char *name)
{
    for (size_t i=0; cp[i].name; i++) {
        if (EQUALS(cp[i].name, name)) {
            return (cp[i].flags & F_BOOL) == F_BOOL;
        } else {
            size_t j;
            for (j=0; cp[i].alts[j]; j++) {
                if (EQUALS(cp[i].alts[j], name)) {
                    return (cp[i].flags & F_BOOL) == F_BOOL;
                }
            }
        }
    }
    
    return 0;
}

void set_one_parameter(void *conf, struct ConfigParameter *cp,
    const char *name, const char *value)
{
    size_t i;
    
    for (i=0; cp[i].name; i++) {
        if (EQUALS(cp[i].name, name)) {
            if (CONF_ERR == cp[i].set(conf, name, value))
                exit(0);
            return;
        } else {
            size_t j;
            for (j=0; cp[i].alts[j]; j++) {
                if (EQUALS(cp[i].alts[j], name)) {
                    if (CONF_ERR == cp[i].set(conf, name, value))
                        exit(0);
                    return;
                }
            }
        }
    }

    fprintf(stderr, "CONF: unknown config option: %s=%s\n", name, value);
    exit(1);
}

void
set_parameters_from_args(void *conf, struct ConfigParameter *cp,
    int argc, char **argv)
{
    int i;
    unsigned name_length;

    for (i=0; i<argc; i++) {

        /*
         * -(-)name=value
         * -(-)name:value
         * -(-)name value
         */
        if (argv[i][0] == '-') {
            unsigned tmp_step = 1;
            /*true:double dashes, false:single dash*/
            if (argv[i][1]=='-')
                tmp_step++;

            const char *argname = argv[i] + tmp_step;
            char name2[64];
            const char *value;

            if (is_numable(cp,argname)) {
                /* May exist by itself like a bool or take an additional
                 * numeric argument */

                /* Look for:
                 * --name=value
                 * --name:value */
                value = strchr(argname, '=');
                if (value == NULL)
                    value = strchr(&argv[i][2], ':');
                if (value) {
                    name_length = (unsigned)(value - argname);
                } else {
                    /* The next parameter contains the name */
                    if (i+1 < argc) {
                        value = argv[i+1];
                        if (isInteger(value) || isBoolean(value))
                            i++;
                        else
                            value = "";
                    } else
                        value = "";
                    name_length = (unsigned)strlen(argname);
                }

                /* create a copy of the name */
                if (name_length > sizeof(name2) - 1) {
                    fprintf(stderr, "%.*s: name too long\n", name_length, argname);
                    name_length = sizeof(name2) - 1;
                }
                memcpy(name2, argname, name_length);
                name2[name_length] = '\0';

                set_one_parameter(conf, cp, name2, value);
            } else {
                value = strchr(&argv[i][2], '=');
                if (value == NULL)
                    value = strchr(&argv[i][2], ':');
                if (value == NULL) {
                    if (is_singleton(cp,argname))
                        value = "";
                    else
                        value = argv[++i];
                    name_length = (unsigned)strlen(argname);
                } else {
                    name_length = (unsigned)(value - argname);
                    value++;
                }

                if (i >= argc) {
                    fprintf(stderr, "%.*s: empty parameter\n", name_length, argname);
                    // break;
                    exit(1);
                }

                if (name_length > sizeof(name2) - 1) {
                    fprintf(stderr, "%.*s: name too long\n", name_length, argname);
                    name_length = sizeof(name2) - 1;
                }

                memcpy(name2, argname, name_length);
                name2[name_length] = '\0';

                set_one_parameter(conf, cp, name2, value);
            }
            continue;
        }

        if (!isdigit(argv[i][0]) && argv[i][0] != ':' && argv[i][0] != '[') {
            fprintf(stderr, "FAIL: unknown command-line parameter \"%s\"\n", argv[i]);
            exit(1);
        }

        /* If parameter doesn't start with '-', assume it's an
         * IPv4 range
         */
        // xconf_set_parameter(xconf, "range", argv[i]);
    }
}

int
set_parameters_from_string(void *conf, struct ConfigParameter *cp, char *string)
{
    int     sub_argc;
    char ** sub_argv;
    
    sub_argv = string_to_args(string, &sub_argc);
    if (!sub_argv) {
        return 1;
    }

    set_parameters_from_args(conf, cp, sub_argc, sub_argv);
    free(sub_argv);
    return 0;
}

int
set_parameters_from_substring(void *conf, struct ConfigParameter *cp, char *substring)
{
    int     sub_argc;
    char ** sub_argv;
    
    sub_argv = substring_to_args(substring, &sub_argc);
    if (!sub_argv) {
        return 1;
    }

    set_parameters_from_args(conf, cp, sub_argc, sub_argv);
    free(sub_argv);
    return 0;
}

/*
    safe C library functions

    This upgrades unsafe C functions like "strcpy()" to safer equivalents,
    like "safe_strcpy()".

    NOTE: This is for maintaining a policy of "no unsafe functions"
*/

#include "safe-string.h"

#include <ctype.h>
#include <string.h>

#include "fine-malloc.h"
#include "../util-out/logger.h"
/**
 * Case-insensitive memcmp()
 */
#ifdef __GNUC__
int memcasecmp(const void *lhs, const void *rhs, size_t length) {
    int i;
    for (i = 0; i < length; i++) {
        if (tolower(((char *)lhs)[i]) != tolower(((char *)rhs)[i]))
            return -1;
    }
    return 0;
}
#endif

/**
 * Safe version of `strcpy()`
 */
void safe_strcpy(char *dst, size_t sizeof_dst, const char *src) {
    size_t i;

    if (sizeof_dst == 0)
        return;

    if (dst == NULL)
        return;

    if (src == NULL) {
        dst[0] = 0;
        return;
    }

    for (i = 0; src[i]; i++) {
        if (i >= sizeof_dst) {
            dst[0] = 0;
            return;
        } else
            dst[i] = src[i];
    }
    if (i >= sizeof_dst) {
        dst[0] = 0;
        return;
    } else
        dst[i] = src[i];

    return;
}

int safe_localtime(struct tm *_tm, const time_t *time) {
    struct tm *x;

    x = localtime(time);
    if (x == NULL) {
        memset(_tm, 0, sizeof(*_tm));
        return -1;
    }
    memcpy(_tm, x, sizeof(*_tm));

    return 0;
}

int safe_gmtime(struct tm *_tm, const time_t *time) {
    struct tm *x;

    x = gmtime(time);
    if (x == NULL) {
        memset(_tm, 0, sizeof(*_tm));
        return -1;
    }
    memcpy(_tm, x, sizeof(*_tm));

    return 0;
}

char *safe_stristr(const char *haystack, const char *needle) {
    char *cp = (char *)haystack;
    char *s1, *s2;

    if (!*needle)
        return ((char *)haystack);

    while (*cp) {
        s1 = cp;
        s2 = (char *)needle;

        while (*s1 && *s2 && toupper(*s1) == toupper(*s2)) {
            s1++, s2++;
        }

        if (!*s2)
            return (cp);

        cp++;
    }

    return (NULL);
}

void *safe_memismem(const void *haystack, size_t haystacklen,
                    const void *needle, size_t needlelen) {
    char *cp = (char *)haystack;
    char *s1, *s2;

    while (*cp) {
        s1 = cp;
        s2 = (char *)needle;

        while ((s1 - (char *)haystack) != haystacklen &&
               (s2 - (char *)needle) != needlelen &&
               toupper(*s1) == toupper(*s2)) {
            s1++, s2++;
        }

        if ((s2 - (char *)needle) == needlelen)
            return (cp);

        cp++;
    }

    return (NULL);
}

void safe_trim(char *line, size_t sizeof_line) {
    if (sizeof_line > strlen(line))
        sizeof_line = strlen(line);

    while (isspace(*line & 0xFF))
        memmove(line, line + 1, sizeof_line--);
    while (*line && isspace(line[sizeof_line - 1] & 0xFF))
        line[--sizeof_line] = '\0';
}

void safe_trim_char(char *line, size_t sizeof_line, char c) {
    if (sizeof_line > strlen(line))
        sizeof_line = strlen(line);

    while (*line == c)
        memmove(line, line + 1, sizeof_line--);
    while (*line && line[sizeof_line - 1] == c)
        line[--sizeof_line] = '\0';
}

const char *safe_normalize_str(const unsigned char *px, size_t length,
                               char *buf, size_t buf_len) {
    size_t i      = 0;
    size_t offset = 0;

    for (i = 0; i < length; i++) {
        unsigned char c = px[i];

        if (isprint(c) && c != '<' && c != '>' && c != '&' && c != '\\' &&
            c != '\"' && c != '\'') {
            if (offset + 2 < buf_len)
                buf[offset++] = px[i];
        } else {
            if (offset + 5 < buf_len) {
                buf[offset++] = '\\';
                buf[offset++] = 'x';
                buf[offset++] = "0123456789abcdef"[px[i] >> 4];
                buf[offset++] = "0123456789abcdef"[px[i] & 0xF];
            }
        }
    }

    buf[offset] = '\0';

    return buf;
}

void *safe_memmem(const void *src, int srclen, const void *trg, int trglen) {
    unsigned char *csrc = (unsigned char *)src;
    unsigned char *ctrg = (unsigned char *)trg;
    unsigned char *tptr, *cptr;
    int            searchlen, ndx = 0;

    /* add some initial error checking if you want */

    while (ndx <= srclen) {
        cptr = &csrc[ndx];
        if ((searchlen = srclen - ndx - trglen + 1) <= 0) {
            return NULL;
        } /* if */
        if ((tptr = memchr(cptr, *ctrg, searchlen)) == NULL) {
            return NULL;
        } /* if */
        if (memcmp(tptr, ctrg, trglen) == 0) {
            return tptr;
        } /* if */
        ndx += tptr - cptr + 1;
    } /* while */

    return NULL;
}

/*************************************************************************
 * I use standard C write this from CommandLineToArgvA_wine.
 * https://github.com/futurist/CommandLineToArgvA.git
 * And CommandLineToArgvA_wine is from CommandLineToArgvA [SHELL32.@]
 *
 * We must interpret the quotes in the command line to rebuild the argv
 * array correctly:
 * - arguments are separated by spaces or tabs
 * - quotes serve as optional argument delimiters
 *   '"a b"'   -> 'a b'
 * - escaped quotes must be converted back to '"'
 *   '\"'      -> '"'
 * - consecutive backslashes preceding a quote see their number halved with
 *   the remainder escaping the quote:
 *   2n   backslashes + quote -> n backslashes + quote as an argument delimiter
 *   2n+1 backslashes + quote -> n backslashes + literal quote
 * - backslashes that are not followed by a quote are copied literally:
 *   'a\b'     -> 'a\b'
 *   'a\\b'    -> 'a\\b'
 * - in quoted strings, consecutive quotes see their number divided by three
 *   with the remainder modulo 3 deciding whether to close the string or not.
 *   Note that the opening quote must be counted in the consecutive quotes,
 *   that's the (1+) below:
 *   (1+) 3n   quotes -> n quotes
 *   (1+) 3n+1 quotes -> n quotes plus closes the quoted string
 *   (1+) 3n+2 quotes -> n+1 quotes plus closes the quoted string
 * - in unquoted strings, the first quote opens the quoted string and the
 *   remaining consecutive quotes follow the above rule.
 */
char **safe_str_to_args(char *string, int *arg_count) {
    int    argc;
    char **argv;
    char  *s;
    char  *d;
    char  *cmdline;
    int    qcount, bcount;

    /*skip spaces*/
    while (*string == ' ')
        string++;

    if (!arg_count || *string == 0) {
        LOG(LEVEL_DEBUG, "string_to_args has invalid parameter.\n");
        return NULL;
    }

    /* --- First count the arguments */
    argc = 1;
    s    = string;
    /* The first argument, the executable path, follows special rules */
    if (*s == '"') {
        /* The executable path ends at the next quote, no matter what */
        s++;
        while (*s)
            if (*s++ == '"')
                break;
    } else {
        /* The executable path ends at the next space, no matter what */
        while (*s && *s != ' ' && *s != '\t')
            s++;
    }
    /* skip to the first argument, if any */
    while (*s == ' ' || *s == '\t')
        s++;
    if (*s)
        argc++;

    /* Analyze the remaining arguments */
    qcount = bcount = 0;
    while (*s) {
        if ((*s == ' ' || *s == '\t') && qcount == 0) {
            /* skip to the next argument and count it if any */
            while (*s == ' ' || *s == '\t')
                s++;
            if (*s)
                argc++;
            bcount = 0;
        } else if (*s == '\\') {
            /* '\', count them */
            bcount++;
            s++;
        } else if (*s == '"') {
            /* '"' */
            if ((bcount & 1) == 0)
                qcount++; /* unescaped '"' */
            s++;
            bcount = 0;
            /* consecutive quotes, see comment in copying code below */
            while (*s == '"') {
                qcount++;
                s++;
            }
            qcount = qcount % 3;
            if (qcount == 2)
                qcount = 0;
        } else {
            /* a regular character */
            bcount = 0;
            s++;
        }
    }

    /* Allocate in a single lump, the string array, and the strings that go
     * with it. This way the caller can make a single LocalFree() call to free
     * both, as per MSDN.
     */
    argv = MALLOC((argc + 1) * sizeof(char *) +
                  (strlen(string) + 1) * sizeof(char));
    if (!argv)
        return NULL;
    cmdline = (char *)(argv + argc + 1);
    safe_strcpy(cmdline,
                (argc + 1) * sizeof(char *) +
                    (strlen(string) + 1) * sizeof(char) - argc - 1,
                string);

    /* --- Then split and copy the arguments */
    argv[0] = d = cmdline;
    argc        = 1;
    /* The first argument, the executable path, follows special rules */
    if (*d == '"') {
        /* The executable path ends at the next quote, no matter what */
        s = d + 1;
        while (*s) {
            if (*s == '"') {
                s++;
                break;
            }
            *d++ = *s++;
        }
    } else {
        /* The executable path ends at the next space, no matter what */
        while (*d && *d != ' ' && *d != '\t')
            d++;
        s = d;
        if (*s)
            s++;
    }
    /* close the executable path */
    *d++ = 0;
    /* skip to the first argument and initialize it if any */
    while (*s == ' ' || *s == '\t')
        s++;
    if (!*s) {
        /* There are no parameters so we are all done */
        argv[argc] = NULL;
        *arg_count = argc;
        return argv;
    }

    /* Split and copy the remaining arguments */
    argv[argc++] = d;
    qcount = bcount = 0;
    while (*s) {
        if ((*s == ' ' || *s == '\t') && qcount == 0) {
            /* close the argument */
            *d++   = 0;
            bcount = 0;

            /* skip to the next one and initialize it if any */
            do {
                s++;
            } while (*s == ' ' || *s == '\t');
            if (*s)
                argv[argc++] = d;
        } else if (*s == '\\') {
            *d++ = *s++;
            bcount++;
        } else if (*s == '"') {
            if ((bcount & 1) == 0) {
                /* Preceded by an even number of '\', this is half that
                 * number of '\', plus a quote which we erase.
                 */
                d -= bcount / 2;
                qcount++;
            } else {
                /* Preceded by an odd number of '\', this is half that
                 * number of '\' followed by a '"'
                 */
                d    = d - bcount / 2 - 1;
                *d++ = '"';
            }
            s++;
            bcount = 0;
            /* Now count the number of consecutive quotes. Note that qcount
             * already takes into account the opening quote if any, as well as
             * the quote that lead us here.
             */
            while (*s == '"') {
                if (++qcount == 3) {
                    *d++   = '"';
                    qcount = 0;
                }
                s++;
            }
            if (qcount == 2)
                qcount = 0;
        } else {
            /* a regular character */
            *d++   = *s++;
            bcount = 0;
        }
    }
    *d         = '\0';
    argv[argc] = NULL;
    *arg_count = argc;

    return argv;
}

/**
 * This func handle single quote rather than quote.
 * So it cannot contains quotes.
 */
char **safe_substr_to_args(char *substring, int *arg_count) {
    int    argc;
    char **argv;
    char  *s;
    char  *d;
    char  *cmdline;
    int    qcount, bcount;

    /*skip spaces*/
    while (*substring == ' ')
        substring++;

    if (!arg_count || *substring == 0) {
        LOG(LEVEL_DEBUG, "string_to_args has invalid parameter.\n");
        return NULL;
    }

    /* --- First count the arguments */
    argc = 1;
    s    = substring;
    /* The first argument, the executable path, follows special rules */
    if (*s == '\'') {
        /* The executable path ends at the next quote, no matter what */
        s++;
        while (*s)
            if (*s++ == '\'')
                break;
    } else {
        /* The executable path ends at the next space, no matter what */
        while (*s && *s != ' ' && *s != '\t')
            s++;
    }
    /* skip to the first argument, if any */
    while (*s == ' ' || *s == '\t')
        s++;
    if (*s)
        argc++;

    /* Analyze the remaining arguments */
    qcount = bcount = 0;
    while (*s) {
        if ((*s == ' ' || *s == '\t') && qcount == 0) {
            /* skip to the next argument and count it if any */
            while (*s == ' ' || *s == '\t')
                s++;
            if (*s)
                argc++;
            bcount = 0;
        } else if (*s == '\\') {
            /* '\', count them */
            bcount++;
            s++;
        } else if (*s == '\'') {
            /* '"' */
            if ((bcount & 1) == 0)
                qcount++; /* unescaped '"' */
            s++;
            bcount = 0;
            /* consecutive quotes, see comment in copying code below */
            while (*s == '\'') {
                qcount++;
                s++;
            }
            qcount = qcount % 3;
            if (qcount == 2)
                qcount = 0;
        } else {
            /* a regular character */
            bcount = 0;
            s++;
        }
    }

    /* Allocate in a single lump, the string array, and the strings that go
     * with it. This way the caller can make a single LocalFree() call to free
     * both, as per MSDN.
     */
    argv = MALLOC((argc + 1) * sizeof(char *) +
                  (strlen(substring) + 1) * sizeof(char));
    if (!argv)
        return NULL;
    cmdline = (char *)(argv + argc + 1);
    safe_strcpy(cmdline,
                (argc + 1) * sizeof(char *) +
                    (strlen(substring) + 1) * sizeof(char) - argc - 1,
                substring);

    /* --- Then split and copy the arguments */
    argv[0] = d = cmdline;
    argc        = 1;
    /* The first argument, the executable path, follows special rules */
    if (*d == '\'') {
        /* The executable path ends at the next quote, no matter what */
        s = d + 1;
        while (*s) {
            if (*s == '\'') {
                s++;
                break;
            }
            *d++ = *s++;
        }
    } else {
        /* The executable path ends at the next space, no matter what */
        while (*d && *d != ' ' && *d != '\t')
            d++;
        s = d;
        if (*s)
            s++;
    }
    /* close the executable path */
    *d++ = 0;
    /* skip to the first argument and initialize it if any */
    while (*s == ' ' || *s == '\t')
        s++;
    if (!*s) {
        /* There are no parameters so we are all done */
        argv[argc] = NULL;
        *arg_count = argc;
        return argv;
    }

    /* Split and copy the remaining arguments */
    argv[argc++] = d;
    qcount = bcount = 0;
    while (*s) {
        if ((*s == ' ' || *s == '\t') && qcount == 0) {
            /* close the argument */
            *d++   = 0;
            bcount = 0;

            /* skip to the next one and initialize it if any */
            do {
                s++;
            } while (*s == ' ' || *s == '\t');
            if (*s)
                argv[argc++] = d;
        } else if (*s == '\\') {
            *d++ = *s++;
            bcount++;
        } else if (*s == '\'') {
            if ((bcount & 1) == 0) {
                /* Preceded by an even number of '\', this is half that
                 * number of '\', plus a quote which we erase.
                 */
                d -= bcount / 2;
                qcount++;
            } else {
                /* Preceded by an odd number of '\', this is half that
                 * number of '\' followed by a '"'
                 */
                d    = d - bcount / 2 - 1;
                *d++ = '\'';
            }
            s++;
            bcount = 0;
            /* Now count the number of consecutive quotes. Note that qcount
             * already takes into account the opening quote if any, as well as
             * the quote that lead us here.
             */
            while (*s == '\'') {
                if (++qcount == 3) {
                    *d++   = '\'';
                    qcount = 0;
                }
                s++;
            }
            if (qcount == 2)
                qcount = 0;
        } else {
            /* a regular character */
            *d++   = *s++;
            bcount = 0;
        }
    }
    *d         = '\0';
    argv[argc] = NULL;
    *arg_count = argc;

    return argv;
}

/***************************************************************************
 ***************************************************************************/
int safe_name_equals(const char *lhs, const char *rhs) {
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return 1; /*arrays*/
        if (*rhs == '\0' && *lhs == '[')
            return 1; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return 0;
        if (*lhs == '\0')
            return 1;
        lhs++;
        rhs++;
    }
}

/***************************************************************************
 * When setting parameters, this will parse integers from the config
 * parameter strings.
 ***************************************************************************/
uint64_t safe_parse_int(const void *vstr, size_t length) {
    const char *str    = (const char *)vstr;
    uint64_t    result = 0;
    size_t      i;

    for (i = 0; i < length; i++) {
        result = result * 10 + (str[i] - '0');
    }
    return result;
}

bool safe_bytes_equals(const void *src, size_t src_len, const void *byt,
                       size_t byt_len) {
    bool equal = false;

    for (size_t i = 0; i < src_len && i < byt_len; i++) {
        if (((unsigned char *)src)[i] != ((unsigned char *)byt)[i])
            break;
        if (i == byt_len - 1)
            equal = true;
    }

    return equal;
}

int safe_iso8601_time(char *format_time, size_t size, const time_t *time) {
#if defined(__MINGW64__) || defined(__MINGW32__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat="
#endif
    return strftime(format_time, size, "%FT%TZ", gmtime(time));
#if defined(__MINGW64__) || defined(__MINGW32__)
#pragma GCC diagnostic pop
#endif
}

void safe_memmove(unsigned char *buf, size_t length, size_t to, size_t from,
                  size_t chunklength) {
    if (chunklength + to > length) {
        // LOG(LEVEL_ERROR, "+"); fflush(stderr);
        chunklength = length - to;
    }
    if (chunklength + from > length) {
        // LOG(LEVEL_ERROR, "-"); fflush(stderr);
        chunklength = length - from;
    }
    memmove(buf + to, buf + from, chunklength);
}

/**
 * Do a memset() of a chunk of memory within a buffer with bounds checking
 */
void safe_memset(unsigned char *buf, size_t length, size_t offset, int c,
                 size_t chunklength) {
    if (chunklength + offset > length) {
        chunklength = length - offset;
        // LOG(LEVEL_ERROR, "*"); fflush(stderr);
    }
    memset(buf + offset, c, chunklength);
}
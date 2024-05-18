/*
    Data Chain

    This module remembers a series of "data" identified by "name".
    These are often simple strings, like the FTP hello string.

    Create by lishRhungry 2024
*/
#ifndef DATA_CHAIN_H
#define DATA_CHAIN_H

#include <stddef.h>

#define DACH_DEFAULT_DATA_SIZE     200
#define DACH_MAX_NAME_SIZE          20

/**
 * A structure for tracking a series of name/data memories
 */
struct DataLink {
    struct DataLink     *next;
    char                 name[DACH_MAX_NAME_SIZE];
    unsigned             name_hash;
    unsigned             data_len;
    unsigned             data_size;
    unsigned char        data[DACH_DEFAULT_DATA_SIZE];
};

struct DataChain {
    struct DataLink     *link;
    unsigned             count;
};

struct DataChainB64
{
    unsigned state:2;
    unsigned temp:24;
};

/**
 * Release all memory.
 */
void
datachain_release(struct DataChain *dach);

/**
 * Append text onto the data. If this exceeds the buffer, then the
 * buffer will be expanded.
 */
void
datachain_append(struct DataChain *dach, const char *name, const void *px, size_t length);

#define AUTO_LEN ((size_t)~0)

void
datachain_printf(struct DataChain *dach, const char *name, const char *fmt, ...);

/**
 * Append a single character to the data.
 */
void
datachain_append_char(struct DataChain *dach, const char *name, int c);

/**
 * Append an integer, with hex digits, with the specified number of
 * digits
 */
void
datachain_append_hexint(struct DataChain *dach, const char *name,
    unsigned long long number, int digits);

void
datachain_append_unicode(struct DataChain *dach, const char *name, unsigned c);

/**
 * Select a specific string (of the specified type).
 */
const unsigned char *
datachain_string(const struct DataChain *dach, const char *name);

/**
 * Get the length of a specific string of the specified type.
 * This is the matching function to datachain_string.
 */
unsigned
datachain_string_length(const struct DataChain *dach, const char *name);


/**
 * Prepare to start calling datachain_append_base64()
 */
void
datachain_init_base64(struct DataChainB64 *base64);

/**
 * Converts the string to BASE64 and appends it to the data.
 * Since this can be called iteratively as new input arrives,
 * a call to datachain_init_base64() must be called before the first fragment,
 * and a call to datachain_finalize_base64() must be called after the last
 * fragment
 */
void
datachain_append_base64(struct DataChain *dach, const char *name,
    const void *vpx, size_t length, struct DataChainB64 *base64);

/**
 * Finish encoding the BASE64 string, appending the '==' things on the
 * end if necessary
 */
void
datachain_finalize_base64(struct DataChain *dach, const char *name,
    struct DataChainB64 *base64);

/**
 * Compares a data string to a fixed string. This is primarily used
 * in the "self-test" feature in order to compare parsed data from
 * expected data.
 */
unsigned
datachain_is_equal(const struct DataChain *dach, const char *name,
    const char *string);

unsigned
datachain_is_contains(const struct DataChain *dach, const char *name,
    const char *string);

/**
 * Do the typical unit/regression test, for this module.
 */
int
datachain_selftest(void);

#endif

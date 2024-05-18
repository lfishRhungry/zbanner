/*
    Data Chain

    This module remembers a series of "name" & "data" identified by id.
    These are often simple strings, like the FTP hello string.

    From masscan's `banout`
    Modified by lishRhungry 2024
*/
#ifndef DATA_CHAIN_H
#define DATA_CHAIN_H

#include <stddef.h>

#define DACH_DEFAULT_SIZE 200

/**
 * A structure for tracking a series of data memories
 */
struct DataChain {
    struct DataChain    *next;
    unsigned             id;
    unsigned             length;
    unsigned             max_length;
    unsigned char        data[DACH_DEFAULT_SIZE];
};

struct DataChainB64
{
    unsigned state:2;
    unsigned temp:24;
};

/**
 * Initialize the list of data. This doesn't allocate any
 * memory, such sets it to zero.
 */
void
datachain_init(struct DataChain *dach);

/**
 * Release any memory. If the list contains only one short
 * data, then no memory was allocated, so nothing gets
 * freed.
 */
void
datachain_release(struct DataChain *dach);

/**
 * Just appends a newline '\n' character. In the future, this may do something
 * more interesting, which is why it's a separate function.
 */
void
datachain_newline(struct DataChain *dach, unsigned id);

/**
 * End the data of the current.
 */
void
datachain_end(struct DataChain *dach, unsigned id);

/**
 * Append text onto the data. If this exceeds the buffer, then the
 * buffer will be expanded.
 */
void
datachain_append(struct DataChain *dach, unsigned id, const void *px, size_t length);

#define AUTO_LEN ((size_t)~0)

void
datachain_printf(struct DataChain *dach, unsigned id, const char *fmt, ...);

/**
 * Append a single character to the data.
 */
void
datachain_append_char(struct DataChain *dach, unsigned id, int c);

/**
 * Append an integer, with hex digits, with the specified number of
 * digits
 */
void
datachain_append_hexint(struct DataChain *dach, unsigned id,
    unsigned long long number, int digits);

void
datachain_append_unicode(struct DataChain *dach, unsigned id, unsigned c);

/**
 * Select a specific string (of the specified type).
 */
const unsigned char *
datachain_string(const struct DataChain *dach, unsigned id);

/**
 * Get the length of a specific string of the specified type.
 * This is the matching function to datachain_string.
 */
unsigned
datachain_string_length(const struct DataChain *dach, unsigned id);


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
datachain_append_base64(struct DataChain *dach, unsigned id,
    const void *px, size_t length, struct DataChainB64 *base64);

/**
 * Finish encoding the BASE64 string, appending the '==' things on the
 * end if necessary
 */
void
datachain_finalize_base64(struct DataChain *dach, unsigned id,
    struct DataChainB64 *base64);

/**
 * Compares a data string to a fixed string. This is primarily used
 * in the "self-test" feature in order to compare parsed data from
 * expected data.
 */
unsigned
datachain_is_equal(const struct DataChain *dach,
    unsigned id, const char *string);

unsigned
datachain_is_contains(const struct DataChain *dach,
    unsigned id, const char *string);

/**
 * Do the typical unit/regression test, for this module.
 */
int
datachain_selftest(void);

#endif

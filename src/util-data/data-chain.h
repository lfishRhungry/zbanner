#ifndef DATA_CHAIN_H
#define DATA_CHAIN_H

#include <stddef.h>

struct DataChainB64
{
    unsigned state:2;
    unsigned temp:24;
};

/**
 * A structure for tracking one or more type of data memories
 * comes from BannerOutput of masscan. I stripped it because
 * we have need data tracking not only for banner but other
 * situation.
 */
struct DataChain {
    struct DataChain    *next;
    unsigned             type;
    unsigned             length;
    unsigned             max_length;
    unsigned char        data[200];
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
datachain_newline(struct DataChain *dach, unsigned proto);

/**
 * End the data of the current.
 */
void
datachain_end(struct DataChain *dach, unsigned proto);

/**
 * Append text onto the data. If this exceeds the buffer, then the
 * buffer will be expanded.
 */
void
datachain_append(struct DataChain *dach, unsigned proto, const void *px, size_t length);
#define AUTO_LEN ((size_t)~0)

void
datachain_printf(struct DataChain *dach, unsigned proto, const char *fmt, ...);

/**
 * Append a single character to the data.
 */
void
datachain_append_char(struct DataChain *dach, unsigned proto, int c);

/**
 * Append an integer, with hex digits, with the specified number of
 * digits
 */
void
datachain_append_hexint(struct DataChain *dach, unsigned proto, unsigned long long number, int digits);

void
datachain_append_unicode(struct DataChain *dach, unsigned proto, unsigned c);

/**
 * Select a specific string (of the specified type).
 */
const unsigned char *
datachain_string(const struct DataChain *dach, unsigned proto);

/**
 * Get the length of a specific string of the specified type.
 * This is the matching function to datachain_string.
 */
unsigned
datachain_string_length(const struct DataChain *dach, unsigned proto);


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
datachain_append_base64(struct DataChain *dach, unsigned proto,
    const void *px, size_t length,
    struct DataChainB64 *base64);

/**
 * Finish encoding the BASE64 string, appending the '==' things on the
 * end if necessary
 */
void
datachain_finalize_base64(struct DataChain *dach, unsigned proto,
                       struct DataChainB64 *base64);

/**
 * Compares a data string to a fixed string. This is primarily used
 * in the "self-test" feature in order to compare parsed data from
 * expected data.
 */
unsigned
datachain_is_equal(const struct DataChain *dach, unsigned proto,
                const char *string);

unsigned
datachain_is_contains(const struct DataChain *dach, unsigned proto,
                const char *string);

/**
 * Do the typical unit/regression test, for this module.
 */
int
datachain_selftest(void);

#endif

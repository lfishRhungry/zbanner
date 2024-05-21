/*
    Data Chain

    This module remembers a series of "data" identified by "name".
    These are often simple strings, like the FTP hello string.
    I provide funcs to append data/string conveniently.

    I try to maintain c string in data by keeping '\0' tail.
    But you can break this by appending special string.

    For out-of-box using and simple iterating, structures are exposed.
    Change internal contents of structures after understanding code.
    C is dangerous and charming, right?

    Datachain was inspired by banout of masscan but with different
    target, usage and internal code.

    Appending new data to link by `dach_link_append...` is efficient than
    `dach_append...` because of no name matching. You can get the corresponding
    datalink pre by `dach_get/find_pre...` or `dach_append...`

    Create by lishRhungry 2024
*/
#ifndef DATA_CHAIN_H
#define DATA_CHAIN_H

#include "../util-misc/cross.h"

#include <stddef.h>

#define DACH_MAX_NAME_SIZE          25

#define DACH_AUTO_LEN ((size_t)~0)

/**
 * A structure for tracking a series of name/data memories
 * NOTE: name length
 */
struct DataLink {
    struct DataLink     *next;
    char                 name[DACH_MAX_NAME_SIZE];
    unsigned             name_hash;
    unsigned             data_len;
    unsigned             data_size;
    unsigned char        data[1]; /*visual studio doesn't support zero size array as member*/
};

/*must init with all zero*/
struct DataChain {
    struct DataLink      link[1]; /*dummy node for using out of the box*/
    unsigned             count;
};

struct DataChainB64
{
    unsigned state:2;
    unsigned temp:24;
};

/**
 * Create a data link with specified capasity by yourself.
 * NOTE: return old pre if the link exists
 * @return the pre of new link
 */
struct DataLink *
dach_new_link(struct DataChain *dach, const char *name, size_t data_size);

/**
 * Release all memory.
 */
void
dach_release(struct DataChain *dach);

/**
 * Find the previous link of target link.
 * Always return a non-null pre.
 * Check pre->next by your-self.
*/
struct DataLink *
dach_find_pre_link(struct DataChain *dach, const char *name);

/**
 * Get data link by name
 * Retrun NULL if does not exist
*/
struct DataLink *
dach_find_link(struct DataChain *dach, const char *name);

/**
 * Find the previous link of target link.
 * If the target link doesn't exist then create it.
*/
struct DataLink *
dach_get_pre_link(struct DataChain *dach, const char *name);

/**
 * Get data link by name
 * If the target link doesn't exist then create it.
*/
struct DataLink *
dach_get_link(struct DataChain *dach, const char *name);

/**
 * Delete a link by inputting its previous link
 * NOTE: pre must not be NULL
*/
void
dach_del_link_by_pre(struct DataChain *dach, struct DataLink *pre);

/**
 * Delete a link by inputting its previous link
*/
void
dach_del_link(struct DataChain *dach, const char *name);

/**
 * Append target link by inputting its previous link.
 * Length can be DACH_AUTO_LEN if px is c string.
 * NOTE: pre & pre->next must not be NULL
*/
void
dach_append_by_pre(struct DataLink *pre, const void *px, size_t length);

/**
 * Append text onto the data.
 * Length can be DACH_AUTO_LEN if px is c string.
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @return the pre of target link.
 */
struct DataLink *
dach_append(struct DataChain *dach, const char *name, const void *px, size_t length);

/**
 * Append a char to target link by inputting its previous link
 * If this exceeds the buffer, then the buffer will be expanded.
 * NOTE: pre & pre->next must not be NULL
*/
void
dach_append_char_by_pre(struct DataLink *pre, int c);


/**
 * Append a char
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @return the pre of target link.
*/
struct DataLink *
dach_append_char(struct DataChain *dach, const char *name, int c);

/**
 * Append an integer, with hex digits, with the specified number of
 * digits
 * If this exceeds the buffer, then the buffer will be expanded.
 * NOTE: pre & pre->next must not be NULL
 */
void
dach_append_hexint_by_pre(struct DataLink *pre,
    unsigned long long number, int digits);

/**
 * Append an integer, with hex digits, with the specified number of
 * digits
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @return the pre of target link.
 */
struct DataLink *
dach_append_hexint(struct DataChain *dach, const char *name,
    unsigned long long number, int digits);

/**
 * Append either a normal character, or the hex form of a UTF-8 string
 * If this exceeds the buffer, then the buffer will be expanded.
 * NOTE: pre & pre->next must not be NULL
*/
void
dach_append_unicode_by_pre(struct DataLink *pre, unsigned c);

/**
 * Append either a normal character, or the hex form of a UTF-8 string
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @return the pre of target link.
*/
struct DataLink *
dach_append_unicode(struct DataChain *dach, const char *name, unsigned c);

/**
 * Printf in datachain version
 * If this exceeds the buffer, then the buffer will be expanded.
 * NOTE: pre & pre->next must not be NULL
*/
void
dach_printf_by_pre(struct DataLink *pre, const char *fmt, ...);

/**
 * Printf in datachain version
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @return the pre of target link.
*/
struct DataLink *
dach_printf(struct DataChain *dach, const char *name, const char *fmt, ...);

/**
 * Append after removing bad characters, especially new lines and HTML
 * control codes.
 * Length can be DACH_AUTO_LEN if px is c string.
 * If this exceeds the buffer, then the buffer will be expanded.
 * NOTE: pre & pre->next must not be NULL
*/
void
dach_append_normalized_by_pre(struct DataLink *pre,
    const void *px, size_t length);

/**
 * Append after removing bad characters, especially new lines and HTML
 * control codes.
 * Length can be DACH_AUTO_LEN if px is c string.
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * NOTE: pre & pre->next must not be NULL
 * @return the pre of target link.
*/
struct DataLink *
dach_append_normalized(struct DataChain *dach, const char *name,
    const void *px, size_t length);

/**
 * NOTE: link must not be NULL
*/
bool
dach_link_contains(struct DataLink *link, const char *string);

bool
dach_contains(struct DataChain *dach, const char *name,
    const char *string);

/**
 * NOTE: link must not be NULL
 */
bool
dach_link_equals(struct DataLink *link, const char *rhs);

bool
dach_equals(struct DataChain *dach, const char *name,
    const char *string);

/**
 * Prepare to start calling dach_append_base64()
 */
void
dach_init_base64(struct DataChainB64 *base64);

/**
 * Converts the string to BASE64 and appends it to the data.
 * Since this can be called iteratively as new input arrives,
 * a call to dach_init_base64() must be called before the first fragment.
 * And a call to dach_finalize_base64() must be called after the last
 * fragment.
 * Length can be DACH_AUTO_LEN if px is c string.
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * NOTE: pre & pre->next must not be NULL
 */
void
dach_append_base64_by_pre(struct DataLink *pre,
    const void *vpx, size_t length, struct DataChainB64 *base64);

/**
 * Converts the string to BASE64 and appends it to the data.
 * Since this can be called iteratively as new input arrives,
 * a call to dach_init_base64() must be called before the first fragment.
 * And a call to dach_finalize_base64() must be called after the last
 * fragment.
 * Length can be DACH_AUTO_LEN if px is c string.
 * If data with this name doesn't exist, it'll be create.
 * @return the pre of target link.
 */
struct DataLink *
dach_append_base64(struct DataChain *dach, const char *name,
    const void *vpx, size_t length, struct DataChainB64 *base64);

/**
 * Finish encoding the BASE64 string, appending the '==' things on the
 * end if necessary
 * NOTE: pre & pre->next must not be NULL
 */
void
dach_finalize_base64_by_pre(struct DataLink *pre, struct DataChainB64 *base64);

/**
 * Finish encoding the BASE64 string, appending the '==' things on the
 * end if necessary.
 * Nothing happens if target link doesn't exist
 * @return the pre of target link.
 */
void
dach_finalize_base64(struct DataChain *dach, const char *name,
    struct DataChainB64 *base64);

/**
 * Do the typical unit/regression test, for this module.
 */
int
datachain_selftest(void);

#endif

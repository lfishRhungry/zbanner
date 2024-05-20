/*
    Data Chain

    This module remembers a series of "data" identified by "name".
    These are often simple strings, like the FTP hello string.

    Create by lishRhungry 2024
*/
#ifndef DATA_CHAIN_H
#define DATA_CHAIN_H

#include "../util-misc/cross.h"

#include <stddef.h>

#define DACH_MAX_NAME_SIZE          20

#define DACH_AUTO_LEN ((size_t)~0)

/**
 * A structure for tracking a series of name/data memories
 */
struct DataLink {
    struct DataLink     *next;
    char                 name[DACH_MAX_NAME_SIZE];
    unsigned             name_hash;
    unsigned             data_len;
    unsigned             data_size;
    unsigned char        data[0];
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
 * Release all memory.
 */
void
dach_release(struct DataChain *dach);

/**
 * find the previous link of target link.
 * always return a non-null pre.
 * check pre->next by your-self.
*/
struct DataLink *
dach_get_pre_link(struct DataChain *dach, const char *name);

/**
 * Get data link by name
 * Retrun NULL if does not exist
*/
struct DataLink *
dach_get_link(struct DataChain *dach, const char *name);

/**
 * delete a link by inputting its previous link
 * NOTE: pre must not be NULL
*/
void
dach_del_link_by_pre(struct DataChain *dach, struct DataLink *pre);

/**
 * delete a link by inputting its previous link
*/
void
dach_del_link(struct DataChain *dach, const char *name);

/**
 * append target link by inputting its previous link.
 * length can be DACH_AUTO_LEN if px is c string.
 * NOTE: pre & pre->next must not be NULL
*/
void
dach_append_by_pre(struct DataLink *pre, const void *px, size_t length);

/**
 * Append text onto the data.
 * length can be DACH_AUTO_LEN if px is c string.
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 */
void
dach_append(struct DataChain *dach, const char *name, const void *px, size_t length);

/**
 * append a char to target link by inputting its previous link
 * If this exceeds the buffer, then the buffer will be expanded.
 * NOTE: pre & pre->next must not be NULL
*/
void
dach_append_char_by_pre(struct DataLink *pre, int c);


/**
 * append a char
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
*/
void
dach_append_char(struct DataChain *dach, const char *name, int c);

/**
 * append an integer, with hex digits, with the specified number of
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
 */
void
dach_append_hexint(struct DataChain *dach, const char *name,
    unsigned long long number, int digits);

/**
 * append either a normal character, or the hex form of a UTF-8 string
 * If this exceeds the buffer, then the buffer will be expanded.
 * NOTE: pre & pre->next must not be NULL
*/
void
dach_append_unicode_by_pre(struct DataLink *pre, unsigned c);

/**
 * append either a normal character, or the hex form of a UTF-8 string
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
*/
void
dach_append_unicode(struct DataChain *dach, const char *name, unsigned c);

/**
 * printf in datachain version
 * If this exceeds the buffer, then the buffer will be expanded.
 * NOTE: pre & pre->next must not be NULL
*/
void
dach_printf_by_pre(struct DataLink *pre, const char *fmt, ...);

/**
 * printf in datachain version
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
*/
void
dach_printf(struct DataChain *dach, const char *name, const char *fmt, ...);

/**
 * append after removing bad characters, especially new lines and HTML
 * control codes.
 * length can be DACH_AUTO_LEN if px is c string.
 * If this exceeds the buffer, then the buffer will be expanded.
 * NOTE: pre & pre->next must not be NULL
*/
void
dach_append_normalized_by_pre(struct DataLink *pre,
    const unsigned char *px, size_t length);

/**
 * append after removing bad characters, especially new lines and HTML
 * control codes.
 * length can be DACH_AUTO_LEN if px is c string.
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * NOTE: pre & pre->next must not be NULL
*/
void
dach_append_normalized(struct DataChain *dach, const char *name,
    const unsigned char *px, size_t length);

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
 * a call to dach_init_base64() must be called before the first fragment,
 * and a call to dach_finalize_base64() must be called after the last
 * fragment
 * length can be DACH_AUTO_LEN if px is c string.
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
 * a call to dach_init_base64() must be called before the first fragment,
 * and a call to dach_finalize_base64() must be called after the last
 * fragment
 * length can be DACH_AUTO_LEN if px is c string.
 * If data with this name doesn't exist, it'll be create.
 */
void
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
 * end if necessary
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

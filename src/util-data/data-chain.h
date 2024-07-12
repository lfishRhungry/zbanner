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

    Appending new data to link by `dach...by_link` is efficient than
    `dach_append...` because of no name matching. You can get the corresponding
    datalink by `dach_get/find_link...` or `dach_append...` funcs.

    We can set is_number to mention the data string present a number or bool
    string(true or false). This is for some output module formatting.

    !NOTE: Everytime operate by a link, update it by returned link.

    Create by lishRhungry 2024
*/
#ifndef DATA_CHAIN_H
#define DATA_CHAIN_H

#include "../util-misc/cross.h"

#include <stddef.h>

#define DACH_MAX_NAME_SIZE     25
#define DACH_DEFAULT_DATA_SIZE 200

/**
 * A double link list structure for tracking a series of name/data memories
 * Why not be a ring? I'd like it to be used out-of-the-box.
 * NOTE: name length
 */
typedef struct DataLink {
    struct DataLink *next;
    struct DataLink *prev;
    char             name[DACH_MAX_NAME_SIZE];
    unsigned         name_hash;
    unsigned         data_len;
    unsigned         data_size;
    /*is this value a number or bool string(true/false)*/
    bool             is_number;
    /*visual studio doesn't support zero size array as member*/
    unsigned char    data[1];
} DataLink;

/**
 * wrapper of a bunch of data links, must be initiated in all zero
 * */
typedef struct DataChain {
    /*dummy node for using out of the box*/
    DataLink link[1];
    unsigned count;
} DataChain;

typedef struct DachBase64 {
    unsigned state : 2;
    unsigned temp  : 24;
} DachBase64;

/**
 * Create a data link with specified capacity by yourself.
 * @param data_size expected capacity, the actual size of data won't be less
 * than DACH_DEFAULT_DATA_SIZE.
 * @param is_number is the link a number type or bool string(true/false)
 * @return link of new link or already existed link
 */
DataLink *dach_new_link(DataChain *dach, const char *name, size_t data_size,
                        bool is_number);

/**
 * Get data link by name
 * @return the expected link, or NULL if it doesn't exist.
 */
DataLink *dach_find_link(DataChain *dach, const char *name);

/**
 * Get data link by name
 * If the target link doesn't exist then create it.
 * @return the expected link
 */
inline DataLink *dach_get_link(DataChain *dach, const char *name) {
    return dach_new_link(dach, name, 1, false);
}

/**
 * Create a data link with formatted name and specified capacity by yourself.
 * @param data_size expected capacity, the actual size of data won't be less
 * than DACH_DEFAULT_DATA_SIZE.
 * @param is_number is the link a number type or bool string(true/false)
 * @return new link or already existed link
 */
DataLink *dach_new_link_printf(DataChain *dach, size_t data_size,
                               bool is_number, const char *fmt_name, ...);

/**
 * Release all memory.
 */
void dach_release(DataChain *dach);

/**
 * Delete a link.
 * Do nothing if it doesn't exist.
 * @param link link to be deleted.
 */
void dach_del_by_link(DataChain *dach, DataLink *link);

/**
 * Delete a link by its name.
 * Do nothing if it doesn't exist.
 */
inline void dach_del_link(DataChain *dach, const char *name) {
    dach_del_by_link(dach, dach_find_link(dach, name));
}

/**
 * Append target link
 * @param link expected link and must not be NULL
 * @param length len of px, can be DACH_AUTO_LEN if px is c string.
 * @return target link after append.
 */
DataLink *dach_append_by_link(DataLink *pre, const void *px, size_t length);

/**
 * Append text onto the data.
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @param length len of px, can be DACH_AUTO_LEN if px is c string.
 * @return target link after append.
 */
DataLink *dach_append(DataChain *dach, const char *name, const void *px,
                      size_t length);

/**
 * Append a char to target link.
 * If this exceeds the buffer, then the buffer will be expanded.
 * @param link expected link and must not be NULL
 * @return target link after append.
 */
DataLink *dach_append_char_by_link(DataLink *link, int c);

/**
 * Append a char
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @return target link after append.
 */
DataLink *dach_append_char(DataChain *dach, const char *name, int c);

/**
 * Append an integer, with hex digits, with the specified number of
 * digits
 * If this exceeds the buffer, then the buffer will be expanded.
 * @param link expected link and must not be NULL
 * @return target link after append.
 */
DataLink *dach_append_hexint_by_link(DataLink *link, unsigned long long number,
                                     int digits);

/**
 * Append an integer, with hex digits, with the specified number of
 * digits
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @return target link after append.
 */
DataLink *dach_append_hexint(DataChain *dach, const char *name,
                             unsigned long long number, int digits);

/**
 * Append either a normal character, or the hex form of a UTF-8 string
 * If this exceeds the buffer, then the buffer will be expanded.
 * @param link expected link and must not be NULL
 * @return target link after append.
 */
DataLink *dach_append_unicode_by_link(DataLink *link, unsigned c);

/**
 * Append either a normal character, or the hex form of a UTF-8 string
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @return target link after append.
 */
DataLink *dach_append_unicode(DataChain *dach, const char *name, unsigned c);

/**
 * Printf in datachain version
 * If this exceeds the buffer, then the buffer will be expanded.
 * @param link expected link and must not be NULL
 * @return target link after append.
 */
DataLink *dach_printf_by_link(DataLink *link, const char *fmt, ...);

/**
 * Printf in datachain version
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @param is_number set link number type or bool string(true/false) if create
 * it.
 * @return target link after append.
 */
DataLink *dach_printf(DataChain *dach, const char *name, bool is_number,
                      const char *fmt, ...);

/**
 * Append after removing bad characters, especially new lines and HTML
 * control codes.
 * If this exceeds the buffer, then the buffer will be expanded.
 * @param link expected link and must not be NULL
 * @param length len of px, can be DACH_AUTO_LEN if px is c string.
 * @return target link after append.
 */
DataLink *dach_append_normalized_by_link(DataLink *link, const void *px,
                                         size_t length);

/**
 * Append after removing bad characters, especially new lines and HTML
 * control codes.
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @param length len of px, can be DACH_AUTO_LEN if px is c string.
 * @return target link after append.
 */
DataLink *dach_append_normalized(DataChain *dach, const char *name,
                                 const void *px, size_t length);

/**
 * @param link target link and must not be NULL
 */
bool dach_link_contains(DataLink *link, const char *string);

/**
 * @return if contains or NULL if name doesn't exist
 */
bool dach_contains(DataChain *dach, const char *name, const char *string);

/**
 * @param link target link and must not be NULL
 */
bool dach_link_equals(DataLink *link, const char *rhs);

/**
 * @return if equals or NULL if name doesn't exist
 */
bool dach_equals(DataChain *dach, const char *name, const char *string);

/**
 * Prepare to start calling dach_append_base64()
 */
void dach_init_base64(struct DachBase64 *base64);

/**
 * Converts the string to BASE64 and appends it to the data.
 * Since this can be called iteratively as new input arrives,
 * a call to dach_init_base64() must be called before the first fragment.
 * And a call to dach_finalize_base64() must be called after the last
 * fragment.
 * If this exceeds the buffer, then the buffer will be expanded.
 * @param link expected link and must not be NULL
 * @param length len of vpx, can be DACH_AUTO_LEN if px is c string.
 * @return target link after append.
 */
DataLink *dach_append_base64_by_link(DataLink *link, const void *vpx,
                                     size_t length, struct DachBase64 *base64);

/**
 * Converts the string to BASE64 and appends it to the data.
 * Since this can be called iteratively as new input arrives,
 * a call to dach_init_base64() must be called before the first fragment.
 * And a call to dach_finalize_base64() must be called after the last
 * fragment.
 * If data with this name doesn't exist, it'll be create.
 * @param length len of vpx, can be DACH_AUTO_LEN if px is c string.
 * @return target link after append.
 */
DataLink *dach_append_base64(DataChain *dach, const char *name, const void *vpx,
                             size_t length, struct DachBase64 *base64);

/**
 * Finish encoding the BASE64 string, appending the '==' things on the
 * end if necessary
 * @param link expected link and must not be NULL
 * @return target link after append.
 */
DataLink *dach_finalize_base64_by_link(DataLink          *link,
                                       struct DachBase64 *base64);

/**
 * Finish encoding the BASE64 string, appending the '==' things on the
 * end if necessary.
 * Nothing happens if target link doesn't exist
 */
void dach_finalize_base64(DataChain *dach, const char *name,
                          struct DachBase64 *base64);

/**
 * Do the typical unit/regression test, for this module.
 */
int datachain_selftest(void);

#endif

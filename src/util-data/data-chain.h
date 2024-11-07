/*
    Data Chain

    This module remembers a series of "value" identified by "name".
    These are often simple strings(e.g. FTP banners.) or other number types.
    I provide funcs to append value(data/string) conveniently.

    For out-of-box using and simple iterating, structures are exposed.
    Change internal contents of structures after understanding code.
    C is dangerous and charming, right?

    Datachain was inspired by `banout` of masscan and `fieldset` of zmap, but
    with different purpose, usage and internal code.

    Appending new value to link by `dach...by_link` is efficient than
    `dach_append...` because of no name matching. You can get the corresponding
    datalink by `dach_get/find_link...` or `dach_append...` funcs.

    We can set link_type to mention the type of the value. This is for pretty
    formatted result style of some output module.

    !NOTE: Everytime operate by a link, update it by returned link.

    Create by sharkocha 2024
*/
#ifndef DATA_CHAIN_H
#define DATA_CHAIN_H

#include "../util-misc/cross.h"

#include <stddef.h>
#include <stdint.h>

#define DACH_MAX_NAME_SIZE     25
#define DACH_DEFAULT_DATA_SIZE 200

/**
 * NOTE: data type means LinkType_Binary or LinkType_String. They are saved in
 * the same way in DataChain but are different in semantics. It is important for
 * some output modules to print or save these two types in different ways.
 */
typedef enum Link_TYPE {
    LinkType_String = 0, /*data type with just printable chars*/
    LinkType_Binary,     /*data type with unprintable chars*/
    LinkType_Bool,
    LinkType_Int,
    LinkType_Double,
} LinkType;

/**
 * A double link list structure for tracking a series of name/value memories
 * Why not be a ring? I'd like it to be used out-of-the-box.
 * NOTE: name length
 */
typedef struct DataLink {
    struct DataLink *next;
    struct DataLink *prev;
    char             name[DACH_MAX_NAME_SIZE];
    unsigned         name_hash;
    LinkType         link_type;
    unsigned         data_len;  /*decription for LinkType_String*/
    unsigned         data_size; /*decription for LinkType_String*/
    union {
        bool          value_bool;
        uint64_t      value_int;
        double        value_double;
        unsigned char value_data[1]; /*MSVC doesn't on-stack zero size array */
    };
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
 * @param data_size expected capacity, the actual size of data type link won't
 * be less than DACH_DEFAULT_DATA_SIZE.
 * @param type valid type of the link.
 * @return link of new link or already existed link
 */
DataLink *dach_new_link(DataChain *dach, const char *name, size_t data_size,
                        LinkType type);

/**
 * Get data link by name.
 * @return the expected link, or NULL if it doesn't exist.
 */
DataLink *dach_find_link(DataChain *dach, const char *name);

/**
 * Get data link by name.
 * If the target link doesn't exist then create it in specified type.
 * @return the expected link
 */
inline DataLink *dach_get_link(DataChain *dach, const char *name,
                               LinkType type) {
    return dach_new_link(dach, name, 1, type);
}

/**
 * Create a data link with formatted name and specified capacity(if data type).
 * @param data_size expected capacity, the actual size of data won't be less
 * than DACH_DEFAULT_DATA_SIZE.
 * @return new link or already existed link
 */
DataLink *dach_new_link_printf(DataChain *dach, size_t data_size, LinkType type,
                               const char *fmt_name, ...);

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
 * Set value to the int type link.
 * @param link expected link and must not be NULL
 * @return target link after append.
 */
DataLink *dach_set_int_by_link(DataLink *link, uint64_t value);

/**
 * Set value to the int type link.
 * If data with this name doesn't exist, it'll be create.
 * @return target link after append.
 */
DataLink *dach_set_int(DataChain *dach, const char *name, uint64_t value);

/**
 * Set value to the double type link.
 * @param link expected link and must not be NULL
 * @return target link after append.
 */
DataLink *dach_set_double_by_link(DataLink *link, double value);

/**
 * Set value to the double type link.
 * If data with this name doesn't exist, it'll be create.
 * @return target link after append.
 */
DataLink *dach_set_double(DataChain *dach, const char *name, double value);

/**
 * Set value to the bool type link.
 * @param link expected link and must not be NULL
 * @return target link after append.
 */
DataLink *dach_set_bool_by_link(DataLink *link, bool value);

/**
 * Set value to the bool type link.
 * If data with this name doesn't exist, it'll be create.
 * @return target link after append.
 */
DataLink *dach_set_bool(DataChain *dach, const char *name, bool value);

/**
 * Append data to the data type link.
 * @param link expected link and must not be NULL
 * @param length len of px, can be DACH_AUTO_LEN if px is c string.
 * @return target link after append.
 */
DataLink *dach_append_by_link(DataLink *pre, const void *px, size_t length);

/**
 * Append data to the data type link.
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @param length len of px, can be DACH_AUTO_LEN if px is c string.
 * @return target link after append.
 */
DataLink *dach_append(DataChain *dach, const char *name, const void *px,
                      size_t length, LinkType type);

/**
 * Append a char to the data type link.
 * If this exceeds the buffer, then the buffer will be expanded.
 * @param link expected link and must not be NULL
 * @return target link after append.
 */
DataLink *dach_append_char_by_link(DataLink *link, int c);

/**
 * Append a char to the data type link.
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @return target link after append.
 */
DataLink *dach_append_char(DataChain *dach, const char *name, int c,
                           LinkType type);

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
 * Append an integer to the data type link, with hex digits, with the specified
 * number of digits.
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @return target link after append.
 */
DataLink *dach_append_hexint(DataChain *dach, const char *name,
                             unsigned long long number, int digits,
                             LinkType type);

/**
 * Append either a normal character, or the hex form of a UTF-8 string to the
 * data type link.
 * If this exceeds the buffer, then the buffer will be expanded.
 * @param link expected link and must not be NULL
 * @return target link after append.
 */
DataLink *dach_append_unicode_by_link(DataLink *link, unsigned c);

/**
 * Append either a normal character, or the hex form of a UTF-8 string to the
 * data type link.
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @return target link after append.
 */
DataLink *dach_append_unicode(DataChain *dach, const char *name, unsigned c,
                              LinkType type);

/**
 * Printf in datachain version for data type link.
 * If this exceeds the buffer, then the buffer will be expanded.
 * @param link expected link and must not be NULL
 * @return target link after append.
 */
DataLink *dach_printf_by_link(DataLink *link, const char *fmt, ...);

/**
 * Printf in datachain version for data type link.
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * @return target link after append.
 */
DataLink *dach_printf(DataChain *dach, const char *name, LinkType type,
                      const char *fmt, ...);

/**
 * Use no escape char for unprinted chars while normalizing the data. This is a
 * previous setting before starting all data chain.
 * NOTE: no escaped char means escape the escaped chars like '\x00' to '\\x00'
 */
void dach_no_escape_char();

/**
 * Append in one line after removing bad characters, especially backslashes and
 * single/double quotes.
 * If this exceeds the buffer, then the buffer will be expanded.
 * NOTE: The normalized string is not standard for JSON string value if use
 * escaped char...
 * @param link expected link and must not be NULL
 * @param length len of px, can be DACH_AUTO_LEN if px is c string.
 * @return target link after append.
 */
DataLink *dach_append_banner_by_link(DataLink *link, const void *px,
                                     size_t length);

/**
 * Append in one line after removing bad characters, especially backslashes and
 * single/double quotes.
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * NOTE: The normalized string is not standard for JSON string value if use
 * escaped char...
 * @param length len of px, can be DACH_AUTO_LEN if px is c string.
 * @return target link after append.
 */
DataLink *dach_append_banner(DataChain *dach, const char *name, const void *px,
                             size_t length, LinkType type);

/**
 * Append valid utf8 chars in one line after removing bad characters, especially
 * backslashes and single/double quotes.
 * If this exceeds the buffer, then the buffer will be expanded.
 * NOTE: The normalized string is not standard for JSON string value if use
 * escaped char...
 * @param link expected link and must not be NULL
 * @param length len of px, can be DACH_AUTO_LEN if px is c string.
 * @return target link after append.
 */
DataLink *dach_append_utf8_by_link(DataLink *link, const void *px,
                                   size_t length);

/**
 * Append valid utf8 chars in one line after removing bad characters, especially
 * backslashes and single/double quotes.
 * If this exceeds the buffer, then the buffer will be expanded.
 * If data with this name doesn't exist, it'll be create.
 * NOTE: The normalized string is not standard for JSON string value if use
 * escaped char...
 * @param length len of px, can be DACH_AUTO_LEN if px is c string.
 * @return target link after append.
 */
DataLink *dach_append_utf8(DataChain *dach, const char *name, const void *px,
                           size_t length, LinkType type);

/**
 * @param link data type link and must not be NULL
 */
bool dach_link_contains_str(DataLink *link, const char *string);

/**
 * @return if the data type link contains or NULL if name doesn't exist
 */
bool dach_contains_str(DataChain *dach, const char *name, const char *string);

/**
 * @param link data type link and must not be NULL
 */
bool dach_link_equals_str(DataLink *link, const char *rhs);

/**
 * @return the data type link if equals or NULL if name doesn't exist
 */
bool dach_equals_str(DataChain *dach, const char *name, const char *string);

/**
 * Prepare to start calling dach_append_base64()
 */
void dach_init_base64(struct DachBase64 *base64);

/**
 * Converts the string to BASE64 and appends it to the data type link.
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
 * Converts the string to BASE64 and appends it to the data type link.
 * Since this can be called iteratively as new input arrives,
 * a call to dach_init_base64() must be called before the first fragment.
 * And a call to dach_finalize_base64() must be called after the last
 * fragment.
 * If data with this name doesn't exist, it'll be create.
 * @param length len of vpx, can be DACH_AUTO_LEN if px is c string.
 * @return target link after append.
 */
DataLink *dach_append_base64(DataChain *dach, const char *name, const void *vpx,
                             size_t length, LinkType type,
                             struct DachBase64 *base64);

/**
 * Finish encoding the BASE64 string, appending the '==' things on the
 * end if necessary
 * @param link expected data type link and must not be NULL
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

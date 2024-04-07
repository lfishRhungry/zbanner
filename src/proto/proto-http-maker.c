#include "proto-http-maker.h"

#include <ctype.h>
#include <string.h>

#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../util-misc/cross.h"

/**
 * We might have an incomplete HTTP request header. Thus, as we insert
 * fields into it, we'll add missing components onto the end.
 */
static size_t
_http_append(unsigned char **inout_header, size_t length1, size_t length2, const char *str)
{
    size_t str_length = strlen(str);

    *inout_header = REALLOC(*inout_header, length1 + length2 + str_length + 1);
    memcpy(*inout_header + length1, str, str_length + 1);

    return str_length;
}

enum What {
    spaces,
    notspaces,
    end_of_line,
    end_of_field
};

static size_t
_skip(enum What what, const unsigned char *hdr, size_t offset, size_t header_length)
{
    switch (what) {
    case notspaces:
        while (offset < header_length && !isspace(hdr[offset]&0xFF))
            offset++;
        break;
    case spaces:
        while (offset < header_length && hdr[offset] != '\n' && isspace(hdr[offset]&0xFF))
            offset++;
        if (offset < header_length && hdr[offset] == '\n') {
            while (offset > 0 && hdr[offset-1] == '\r')
                offset--;
        }
        break;
    case end_of_field:
        while (offset < header_length && hdr[offset] != '\n')
            offset++;
        if (offset < header_length && hdr[offset] == '\n') {
            while (offset > 0 && hdr[offset-1] == '\r')
                offset--;
        }
        break;
    case end_of_line:
        while (offset < header_length && hdr[offset] != '\n')
            offset++;
        if (offset < header_length && hdr[offset] == '\n')
            offset++;
        break;
    }
    return offset;
}

/**
 * Used when editing our HTTP prototype request, it replaces the existing
 * field (start..end) with the new field. The header is resized and data moved
 * to accommodate this insertion.
 */
static size_t
_http_insert(unsigned char **r_hdr, size_t start, size_t end, size_t header_length, size_t field_length, const void *field)
{
    size_t old_field_length = (end-start);
    size_t new_header_length = header_length + field_length - old_field_length;
    unsigned char *hdr;

    *r_hdr = REALLOC(*r_hdr, new_header_length + 1);
    hdr = *r_hdr;
    
    /* Shrink/expand the field */
    memmove(&hdr[start + field_length], &hdr[end], header_length - end + 1);

    /* Insert the new header at this location */
    memcpy(&hdr[start], field, field_length);

    return new_header_length;
}

/***************************************************************************
 ***************************************************************************/
size_t
http_change_requestline(
    unsigned char **hdr,
    size_t header_length,
    const void *field,
    size_t field_length,
    enum http_req_field item)
{
    size_t offset;
    size_t start;

    /* If no length given, calculate length */
    if (field_length == ~(size_t)0)
        field_length = strlen((const char *)field);

    /*  GET /example.html HTTP/1.0 
     * 0111233333333333334
     * #0 skip leading whitespace
     * #1 skip past method
     * #2 skip past space after method
     * #3 skip past URL field
     * #4 skip past space after URL
     * #5 skip past version
     */

    /* #0 Skip leading whitespace */
    offset = 0;
    offset = _skip(spaces, *hdr, offset, header_length);

    /* #1 Method */
    start = offset;
    if (offset == header_length)
        header_length += _http_append(hdr, header_length, field_length, "GET");
    offset = _skip(notspaces, *hdr, offset, header_length);
    if (item == http_req_method) {
        return _http_insert(hdr, start, offset, header_length, field_length, field);
    }

    /* #2 Method space */
    if (offset == header_length)
        header_length += _http_append(hdr, header_length, field_length, " ");
    offset = _skip(spaces, *hdr, offset, header_length);

    /* #3 URL */
    start = offset;
    if (offset == header_length)
        header_length += _http_append(hdr, header_length, field_length, "/");
    offset = _skip(notspaces, *hdr, offset, header_length);
    if (item == http_req_url) {
        return _http_insert(hdr, start, offset, header_length, field_length, field);
    }

    /* #4 Space after URL */
    if (offset == header_length)
        header_length += _http_append(hdr, header_length, field_length, " ");
    offset = _skip(spaces, *hdr, offset, header_length);

    /* #5 version */
    start = offset;
    if (offset == header_length)
        header_length += _http_append(hdr, header_length, field_length, "HTTP/1.0");
    offset = _skip(notspaces, *hdr, offset, header_length);
    if (item == http_req_version) {
        return _http_insert(hdr, start, offset, header_length, field_length, field);
    }

    /* ending line */
    if (offset == header_length)
        header_length += _http_append(hdr, header_length, field_length, "\r\n");
    offset = _skip(spaces, *hdr, offset, header_length);
    offset = _skip(end_of_line, *hdr, offset, header_length);

    /* now find a blank line */
    for (;;) {
        /* make sure there's at least one line left */
        if (offset == header_length)
            header_length += _http_append(hdr, header_length, field_length, "\r\n");
        if (offset + 1 == header_length && (*hdr)[offset] == '\r')
            header_length += _http_append(hdr, header_length, field_length, "\n");

        start = offset;
        offset = _skip(end_of_field, *hdr, offset, header_length);
        if (start == offset) {
            /* We've reached the end of the header*/
            offset = _skip(end_of_line, *hdr, offset, header_length);
            break;
        }

        if (offset == header_length)
            header_length += _http_append(hdr, header_length, field_length, "\r\n");
        if (offset + 1 == header_length && (*hdr)[offset] == '\r')
            header_length += _http_append(hdr, header_length, field_length, "\n");
        offset = _skip(end_of_line, *hdr, offset, header_length);
    }

    start = offset;
    offset = header_length;
    if (item == http_req_payload) {
        return _http_insert(hdr, start, offset, header_length, field_length, field);
    }
    

    return header_length;
}

static size_t
_field_length(const unsigned char *hdr, size_t offset, size_t hdr_length)
{
    size_t original_offset = offset;

    /* Find newline */
    while (offset < hdr_length && hdr[offset] != '\n')
        offset++;

    /* Trim trailing whitespace */
    while (offset > original_offset && isspace(hdr[offset-1]&0xFF))
        offset--;

    return offset - original_offset;
}

static size_t _next_field(const unsigned char *hdr, size_t offset, size_t hdr_length)
{
    size_t original_offset = offset;

    /* Find newline */
    while (offset < hdr_length && hdr[offset] != '\n')
        offset++;

    /* Remove newline too*/
    if (offset > original_offset && isspace(hdr[offset-1]&0xFF))
        offset++;

    return offset;
}

static bool 
_has_field_name(const char *name, size_t name_length, const unsigned char *hdr, size_t offset, size_t hdr_length)
{
    size_t x;
    bool found_colon = false;

    /* Trim leading whitespace */
    while (offset < hdr_length && isspace(hdr[offset]&0xFF) && hdr[offset] != '\n')
        offset++;

    /* Make sure there's enough space left */
    if (hdr_length - offset < name_length)
        return false;

    /* Make sure there's colon after */
    for (x = offset + name_length; x<hdr_length; x++) {
        unsigned char c = hdr[x] & 0xFF;
        if (isspace(c))
            continue;
        else if (c == ':') {
            found_colon = true;
            break;
        } else {
            /* some unexpected character was found in the name */
            return false;
        }
    }
    if (!found_colon)
        return false;

    /* Compare the name (case insensitive) */
    return memcasecmp(name, hdr + offset, name_length) == 0;
}


/***************************************************************************
 ***************************************************************************/
size_t
http_change_field(unsigned char **inout_header, size_t header_length,
                    const char *name,
                    const unsigned char *value, size_t value_length,
                    enum http_field_action what)
{
    unsigned char *hdr = *inout_header;
    size_t name_length = strlen(name);
    size_t offset;
    size_t next_offset;

    /* If field 'name' ends in a colon, trim that. Also, trim whitespace */
    while (name_length) {
        unsigned char c = name[name_length-1];
        if (c == ':' || isspace(c & 0xFF))
            name_length--;
        else
            break;
    }

    /* If length of the fiend value not specified, then assume
     * nul-terminated string */
    if (value_length == ~(size_t)0)
        value_length = strlen((const char *)value);

    /* Find our field */
    for (offset = _next_field(hdr, 0, header_length); 
        offset < header_length; 
        offset = _next_field(hdr, offset, header_length)) {

        if (_has_field_name(name, name_length, hdr, offset, header_length)) {
            break;
        } else if (_field_length(hdr, offset, header_length) == 0) {
            /* We reached end without finding field, so insert before end
             * instead of replacing an existing header. */
            if (what == http_field_remove)
                return header_length;
            what = http_field_add;
            break;
        }
    }

    /* Allocate a new header to replace the old one. We'll allocated
     * more space than we actually need */
    *inout_header = REALLOC(*inout_header, header_length + name_length + 2 + value_length + 2 + 1 + 2);
    hdr = *inout_header;

    /* If we reached the end without finding proper termination, then add
     * it */
    if (offset == header_length) {
        if (offset == 0 || hdr[offset-1] != '\n') {
            if (hdr[offset-1] == '\r')
                header_length = _http_append(&hdr, header_length, value_length+2, "\n");
            else
                header_length = _http_append(&hdr, header_length, value_length+2, "\r\n");
        }
    }


    /* Make room for the new header */
    next_offset = _next_field(hdr, offset, header_length);
    if (value == NULL || what == http_field_remove) {
        memmove(&hdr[offset + 0],
                &hdr[next_offset],
                header_length - next_offset + 1);
        header_length += 0 - (next_offset - offset);
        return header_length;
    } else if (what == http_field_replace) {
        /* Replace existing field */
        memmove(&hdr[offset + name_length + 2 + value_length + 2],
                &hdr[next_offset],
                header_length - offset + 1);
        header_length += (name_length + 2 + value_length + 2) - (next_offset - offset);
    } else {
        /* Add a new field onto the end */
        memmove(&hdr[offset + name_length + 2 + value_length + 2],
                &hdr[offset],
                header_length - offset + 1);
        header_length += (name_length + 2 + value_length + 2);
    }
    hdr[header_length] = '\0';

    /* Copy the new header */
    memcpy(&hdr[offset], name, name_length);
    memcpy(&hdr[offset + name_length], ": ", 2);
    memcpy(&hdr[offset + name_length + 2], value, value_length);
    memcpy(&hdr[offset + name_length + 2 + value_length], "\r\n", 2);

    return header_length;
}

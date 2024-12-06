#ifndef PROTO_HTTP_MAKER_H
#define PROTO_HTTP_MAKER_H

#include <stddef.h>

enum http_field_action {
    http_field_replace,
    http_field_add,
    http_field_remove,
    http_field_method,
    http_field_url,
    http_field_version,
};

/**
 * Called during configuration when processing a command-line option
 * like "--http-field <name=value>" to add/change a field in the HTTP
 * header.
 * NOTE: *inout_header must be a malloced memory
 *
 * @return
 *   the new length of the header (expanded or shrunk)
 */
size_t http_change_field(unsigned char **inout_header, size_t header_length,
                         const char          *field_name,
                         const unsigned char *field_value,
                         size_t field_value_len, enum http_field_action what);

enum http_req_field {
    http_req_method  = 0,
    http_req_url     = 1,
    http_req_version = 2,
    http_req_payload = 3,
};

/**
 * Called during configuration when processing a command-line option
 * like "--http-url /foo.html". This replaces whatever the existing
 * URL is into the new one.
 * NOTE: *inout_header must be a malloced memory
 *
 * @return
 *   the new length of the header (expanded or shrunk)
 */
size_t http_change_requestline(unsigned char **inout_header,
                               size_t header_length, const void *url,
                               size_t url_length, enum http_req_field item);

int proto_http_maker_selftest();

#endif

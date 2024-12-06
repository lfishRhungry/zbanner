#ifndef PROTO_DATAPASS_H
#define PROTO_DATAPASS_H

#include <stdio.h>
#include <stdbool.h>

/**
 * DataPass is a media of different protocol layer to pass data
 * and its control info.
 * DataPass makes nested protocol possible. e.g. TLS
 *
 * the `is_dynamic` switch means we just pass 2 type of data:
 * 1.static data: we can promise it unchanged for a while until we sending it.
 * 2.dynamic data: we copy it to a MALLOC addr, and who got the datapass will
 * free it for responsibility.
 * */
typedef struct PassedData {
    unsigned char *data;
    size_t         len;
    unsigned       is_dynamic : 1;
    unsigned       is_close   : 1;
} DataPass;

/**
 * Just a wrapper to set dynamic or static data.
 * !set `is_close` by yourself
 */
void datapass_set_data(DataPass *pass, unsigned char *data, size_t len,
                       bool is_dynamic);

#endif
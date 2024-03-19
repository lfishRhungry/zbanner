#ifndef PROTO_DATAPASS_H
#define PROTO_DATAPASS_H

#include <stdio.h>

/**
 * DataPass is a media of different protocol layer to pass data
 * and its control info.
 * DataPass makes nested protocol possible. e.g. TLS
 * */
enum PassFlag {
    PASS__static = 0,    /* it's static data, so the send function can point to it */
    PASS__copy   = 1,    /* the send function must copy the data */
    PASS__adopt  = 2,    /* the buffer was just allocated, so the send function can adopt the pointer */
};
struct DataPass {
  unsigned char *payload;
  size_t         len;
  enum PassFlag  flag:3;
  unsigned       close:1;
};

#endif
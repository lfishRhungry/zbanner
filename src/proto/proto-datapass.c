#include "proto-datapass.h"

#include "../util-data/fine-malloc.h"

#include <string.h>

void datapass_set_data(DataPass *pass, unsigned char *data, size_t len,
                       bool is_dynamic) {
    /*do a safe check for no payload*/
    if (!data || !len) {
        pass->data       = NULL;
        pass->len        = 0;
        pass->is_dynamic = 0;
        return;
    }
    if (is_dynamic) {
        /*dynamic data*/
        pass->data = MALLOC(len);
        memcpy(pass->data, data, len);
        pass->is_dynamic = 1;
    } else {
        /*static data*/
        pass->data = data;
    }

    pass->len = len;

    return;
}
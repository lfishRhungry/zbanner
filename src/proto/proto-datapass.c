#include "proto-datapass.h"

#include "../util/fine-malloc.h"

#include <string.h>

void datapass_set_data(struct DataPass *pass, unsigned char *payload,
    size_t payload_len, unsigned is_dynamic)
{
    /*do a safe check for no payload*/
    if (!payload || !payload_len) {
        pass->payload    = NULL;
        pass->len        = 0;
        pass->is_dynamic = 0;
        return;
    }
    if (is_dynamic) {
        /*dynamic data*/
        pass->payload = MALLOC(payload_len);
        memcpy(pass->payload, payload, payload_len);
        pass->is_dynamic = 1;
    } else {
        /*static data*/
        pass->payload = payload;
    }

    pass->len = payload_len;

    return;
}
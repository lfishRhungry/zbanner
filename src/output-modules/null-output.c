#include "output-modules.h"

#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../pixie/pixie-file.h"

extern struct OutputModule NullOutput; /*for internal x-ref*/

struct OutputModule NullOutput = {
    .name               = "null",
    .need_file          = 0,
    .params             = NULL,
    .init_cb            = &output_init_nothing,
    .result_cb          = &output_result_nothing,
    .close_cb           = &output_close_nothing,
    .desc =
        "NullOutput doesn't save any results and is convenient for debugging. ",
};
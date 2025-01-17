#include "output-modules.h"

extern Output NullOutput; /*for internal x-ref*/

Output NullOutput = {
    .name      = "null",
    .need_file = false,
    .params    = NULL,
    .desc =
        "NullOutput doesn't save any results and is convenient for debugging.",

    .init_cb   = &output_init_nothing,
    .result_cb = &output_result_nothing,
    .close_cb  = &output_close_nothing,
};
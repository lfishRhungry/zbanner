#ifndef OUTPUT_MODULES_H
#define OUTPUT_MODULES_H

#include <time.h>
#include <ctype.h>

#include "../proto/proto-preprocess.h"

void
output_tmp(
    struct PreprocessedInfo * parsed,
    time_t timestamp, unsigned successed,
    const char *classification, const char *report,
    unsigned is_show_failed);

#endif
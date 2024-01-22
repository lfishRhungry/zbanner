#ifndef OUTPUT_MODULES_H
#define OUTPUT_MODULES_H

#include <time.h>
#include <ctype.h>

#include "../scan-modules/scan_modules.h"

void
output_tmp(
    struct PreprocessedInfo * parsed,
    time_t timestamp, unsigned successed,
    const char *classification, const char *report
);

#endif
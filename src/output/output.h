#ifndef OUTPUT_H
#define OUTPUT_H

#include <time.h>
#include <ctype.h>

#include "../proto/proto-preprocess.h"

struct Output{
    char output_filename[256];
    FILE *output_file;
    unsigned is_append:1;
    unsigned is_interactive:1;
    unsigned is_show_failed:1;
    unsigned is_show_report:1;
};

void
output_result(
    struct Output *output,
    struct PreprocessedInfo * parsed,
    time_t timestamp, unsigned successed,
    const char *classification, const char *report);

#endif
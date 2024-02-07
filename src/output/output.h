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
};

/*prepare for outputing results*/
void
output_init(struct Output *output);

void
output_result(
    const struct Output *output,
    const struct PreprocessedInfo *parsed,
    time_t timestamp, unsigned successed,
    const char *classification, const char *report);

/*destroy resources of output*/
void
output_close(struct Output *output);

#endif
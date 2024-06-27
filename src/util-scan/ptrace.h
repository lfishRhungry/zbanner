#ifndef ptrace_h
#define ptrace_h
#include <stdio.h>
#include <stdint.h>

#include "../util-misc/cross.h"


void packet_trace(FILE *fp, double pt_trace,
    const unsigned char *px, size_t length, bool is_sent);


#endif

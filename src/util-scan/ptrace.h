#ifndef PTRACE_H
#define PTRACE_H
#include <stdio.h>
#include <stdint.h>

#include "../util-misc/cross.h"

void packet_trace(FILE *fp, double pt_trace, const unsigned char *px,
                  size_t length, bool is_sent);

#endif

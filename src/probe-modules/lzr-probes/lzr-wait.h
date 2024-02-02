#include "../probe-modules.h"

#ifndef LZR_WAIT_PROBE_H
#define LZR_WAIT_PROBE_H

void
report_nothing(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    const unsigned char *px, unsigned sizeof_px,
    unsigned *successed,
    char *classification, unsigned cls_length,
    char *report, unsigned rpt_length
);

#endif
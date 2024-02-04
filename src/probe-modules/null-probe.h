#include "probe-modules.h"

#ifndef NULL_PROBE_H
#define NULL_PROBE_H

void
just_report_banner(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    const unsigned char *px, unsigned sizeof_px,
    char *report, unsigned rpt_length);

#endif
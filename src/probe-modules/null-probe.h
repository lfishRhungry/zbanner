#include "probe-modules.h"

#ifndef NULL_PROBE_H
#define NULL_PROBE_H

size_t
make_no_payload(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    unsigned cookie,
    unsigned char *payload_buf,
    size_t buf_length);

void
just_report_banner(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    const unsigned char *px, unsigned sizeof_px,
    unsigned *successed,
    char *classification, unsigned cls_length,
    char *report, unsigned rpt_length);

#endif
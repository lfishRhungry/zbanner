#include "stateless-probes.h"

#ifndef NULL_PROBE_H
#define NULL_PROBE_H

size_t
make_no_payload(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me,
    unsigned char *payload_buf, size_t buf_len);

size_t
just_report_banner(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me,
    const unsigned char *banner, size_t banner_len,
    unsigned char *report_banner_buf, size_t buf_len);

size_t
null_get_payload_length(ipaddress ip_them, ipaddress ip_me, unsigned port_them, unsigned port_me);

#endif
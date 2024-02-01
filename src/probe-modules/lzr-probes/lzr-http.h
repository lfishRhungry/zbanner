#include "../probe-modules.h"
#include "../../xconf.h"

#ifndef LZR_HTTP_PROBE_H
#define LZR_HTTP_PROBE_H

static char lzr_http_fmt[] = "GET / HTTP/1.1\r\n"
    "Host: %s:%u\r\n"
    "User-Agent: Mozilla/5.0 "XTATE_WITH_VERSION"\r\n"
    "Accept: */*\r\n"
    "Accept-Encoding: gzip\r\n"
    "\r\n";

size_t
lzr_http_make_payload(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me,
    unsigned char *payload_buf, size_t buf_len);

size_t
lzr_http_get_payload_length(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me);

size_t
lzr_http_report_banner(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me,
    const unsigned char *banner, size_t banner_len,
    unsigned char *report_banner_buf, size_t buf_len);

#endif
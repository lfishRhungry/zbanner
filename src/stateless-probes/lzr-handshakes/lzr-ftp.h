#include "../stateless-probes.h"

#ifndef LZR_FTP_PROBE_H
#define LZR_FTP_PROBE_H

size_t
lzr_ftp_report_banner(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me,
    const unsigned char *banner, size_t banner_len,
    unsigned char *report_banner_buf, size_t buf_len);

#endif
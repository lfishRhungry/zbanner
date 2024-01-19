#include "../stateless-probes.h"

#ifndef LZR_PROBE_H
#define LZR_PROBE_H

#define LZR_SUBPROBE_NAME_LEN 20

static int lzr_global_init(const void *Xconf);

static size_t
lzr_report_banner(ipaddress ip_them, ipaddress ip_me,
	unsigned port_them, unsigned port_me,
	const unsigned char *banner, size_t banner_len,
	unsigned char *report_banner_buf, size_t buf_len);

#endif
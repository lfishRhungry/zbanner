#include "../masscan.h"
#include "stateless-probes.h"

static size_t
null_make_payload(ipaddress ip_them, ipaddress ip_me,
	unsigned port_them, unsigned port_me,
	unsigned char *payload_buf, size_t buf_len)
{
	return 0;
}

static size_t
null_get_payload_length(ipaddress ip_them, ipaddress ip_me, unsigned port_them, unsigned port_me)
{
	return 0;
}

static size_t
null_get_report_banner(ipaddress ip_them, ipaddress ip_me,
	unsigned port_them, unsigned port_me,
	const unsigned char *banner, size_t banner_len,
	unsigned char *report_banner_buf, size_t buf_len)
{
	size_t len = banner_len<=buf_len?banner_len:buf_len;
	memcpy(report_banner_buf, banner, len);
	return len;
}

struct StatelessProbe NullProbe = {
	.name = "null",
	.help_text =
		"NullProbe does not send any data to target port throught and after TCP"
		" handshakes, just wait banner from server. However, waiting is the che"
		"apest thing in stateless mode.",
	.global_init = NULL,
	.thread_init = NULL,
	.make_payload = &null_make_payload,
	.get_payload_length = &null_get_payload_length,
	.get_report_banner = &null_get_report_banner,
	.close = NULL
};
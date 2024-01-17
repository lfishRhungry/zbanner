#include <stdlib.h>

#include "../massip/massip-addr.h"

#ifndef STATELESS_PROBES_H
#define STATELESS_PROBES_H

#define STATELESS_PAYLOAD_MAX_LEN 1460
#define STATELESS_BANNER_MAX_LEN 1460
#define STATELESS_PROBE_ARGS_LEN 256

enum StatelessProbeType {
	Raw_Probe = 0, /*This is for transmit-layer*/
	Tcp_Probe = 1, /*Only use it until now*/
	Udp_Probe = 2,
};


/**
 * masscan.h need to includes stateless-probes.h
 * and struct Masscan/ThreadPair must be used here.
 * Use 'void' to avoid circular dependency,
 * cast it to correct type in specific implementation of probe.
 * @return EXIT_FAILURE to exit process if init failed
*/
typedef int (*stateless_probe_global_init_cb)(const void *Masscan);

/**
 * !Must be thread safe.
*/
typedef int (*stateless_probe_thread_init_cb)(const void *RxThread);

/**
 * @return length of payload data
 * !Must be thread safe.
*/
typedef size_t
(*stateless_probe_make_payload_cb)(
	ipaddress ip_them,
	ipaddress ip_me,
	unsigned port_them,
	unsigned port_me,
	unsigned char *payload_buf,
	size_t payload_buf_length);

/**
 * It's useful when payload is dynamic in target IP/port.
 * !Must be thread safe.
*/
typedef size_t
(*stateless_probe_get_payload_length_cb)(
	ipaddress ip_them,
	ipaddress ip_me,
	unsigned port_them,
	unsigned port_me);

/**
 * Get a "report_banner" to output by output_report_banner func
 * when use `--capture stateless`.
 * Report banner can be same to original banner, or can be some other info:
 * eg. protocol type, verification, special results...
 * @return length of report banner data
 * !Must be thread safe.
 */
typedef size_t
(*stateless_probe_get_report_banner_cb)(
	ipaddress ip_them,
	ipaddress ip_me,
	unsigned port_them,
	unsigned port_me,
	const unsigned char *banner,
	size_t banner_length,
	unsigned char *report_banner_buf,
	size_t report_banner_buf_length);

typedef int (*stateless_probe_close_cb)(const void *Masscan);

struct StatelessProbe
{
	const char *name;
	const char *help_text;
	const enum StatelessProbeType type;

	stateless_probe_global_init_cb global_init;
	stateless_probe_thread_init_cb thread_init;
	stateless_probe_make_payload_cb make_payload;
	stateless_probe_get_payload_length_cb get_payload_length;
	stateless_probe_get_report_banner_cb get_report_banner;
	stateless_probe_close_cb close;
};

struct StatelessProbe *get_stateless_probe(const char *name);

void list_all_probes();

#endif
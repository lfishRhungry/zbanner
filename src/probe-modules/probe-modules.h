#include <stdlib.h>

#include "../massip/massip-addr.h"

#ifndef PROBE_MODULES_H
#define PROBE_MODULES_H

#define STATELESS_PAYLOAD_MAX_LEN 1460
#define STATELESS_BANNER_MAX_LEN 1460

enum ProbeModuleType {
    Raw_Probe = 0, /*This is for transmit-layer*/
    Tcp_Probe = 1, /*Only use it until now*/
    Udp_Probe = 2,
};


/**
 * xconf.h need to includes this file
 * and struct Xconf/Thread must be used here.
 * Use 'void' to avoid circular dependency,
 * cast it to correct type in specific implementation of probe.
 * @return EXIT_FAILURE to exit process if init failed
*/
typedef int (*probe_modules_global_init)(const void *Xconf);

/**
 * !Must be thread safe.
*/
typedef int (*probe_modules_thread_init)(const void *RxThread);

/**
 * @return length of payload data
 * !Must be thread safe.
*/
typedef size_t
(*probe_modules_make_payload)(
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
(*probe_modules_get_payload_length)(
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
(*probe_modules_get_report_banner)(
    ipaddress ip_them,
    ipaddress ip_me,
    unsigned port_them,
    unsigned port_me,
    const unsigned char *banner,
    size_t banner_length,
    unsigned char *report_banner_buf,
    size_t report_banner_buf_length);

typedef int (*probe_modules_close)(const void *Xconf);

struct ProbeModule
{
    const char *name;
    const char *help_text;
    const enum ProbeModuleType type;

    probe_modules_global_init global_init_cb;
    probe_modules_thread_init thread_init_cb;
    probe_modules_make_payload make_payload_cb;
    probe_modules_get_payload_length get_payload_length_cb;
    probe_modules_get_report_banner get_report_banner_cb;
    probe_modules_close close_cb;
};

struct ProbeModule *get_probe_module_by_name(const char *name);

void list_all_probe_modules();

#endif
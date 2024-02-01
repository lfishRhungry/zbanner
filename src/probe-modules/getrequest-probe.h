#include "probe-modules.h"

#ifndef GETREQUEST_PROBE_H
#define GETREQUEST_PROBE_H

#define GETREQUEST_PAYLOAD "GET / HTTP/1.0\r\n\r\n"

size_t
getrequest_make_payload(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me,
    unsigned char *payload_buf, size_t buf_len);

size_t
getrequest_get_payload_length(ipaddress ip_them, ipaddress ip_me, unsigned port_them, unsigned port_me);

#endif
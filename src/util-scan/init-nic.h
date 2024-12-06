#ifndef INIT_NIC_H
#define INIT_NIC_H

#include <stdbool.h>

typedef struct XtateConf XConf;

/**
 * Init struct NIC and adapter within it.
 *
 * Discover the local network adapter parameters, such as which
 * MAC address we are using and the MAC addresses of the
 * local routers.
 */
int init_nic(XConf *xconf, bool has_ipv4_targets, bool has_ipv6_targets);

#endif

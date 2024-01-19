#ifndef INITADAPTER_H
#define INITADAPTER_H

#include "../xconf.h"


/**
 * Discover the local network adapter parameters, such as which
 * MAC address we are using and the MAC addresses of the
 * local routers.
 */
int
initialize_adapter(struct Xconf *xconf);

#endif

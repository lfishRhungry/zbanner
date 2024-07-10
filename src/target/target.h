#ifndef TARGET_H
#define TARGET_H

#include "target-addr.h"

/**
 * Abstract common attributes for a single scanning target
 */
typedef struct Target {
    /**IP proto number to mention whether it is TCP, UDP, etc.*/
    unsigned           ip_proto;
    ipaddress          ip_them;
    ipaddress          ip_me;
    unsigned           port_them;
    unsigned           port_me;
} Target;

#endif
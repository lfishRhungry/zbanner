#ifndef TARGET_H
#define TARGET_H

#include "target-addr.h"

/**
 * Abstract common attributes for a single scanning target
 */
typedef struct Target {
    /*IP proto number to mention whether it is TCP, UDP, etc.*/
    unsigned  ip_proto;
    /*IP of target*/
    ipaddress ip_them;
    /*IP of me*/
    ipaddress ip_me;
    /*actual port number of target*/
    unsigned  port_them;
    /*actual port number of me*/
    unsigned  port_me;
} Target;

#endif
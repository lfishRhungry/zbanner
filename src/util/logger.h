#ifndef LOGGER_H
#define LOGGER_H
#include "../massip/massip-addr.h"

void LOG(int level, const char *fmt, ...);
void LOGip(int level, ipaddress ip, unsigned port, const char *fmt, ...);
void LOGnet(unsigned port_me, ipaddress ip_them, const char *fmt, ...);


void LOG_add_level(int level);
int LOG_get_level();

#endif
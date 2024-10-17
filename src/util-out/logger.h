#ifndef LOGGER_H
#define LOGGER_H
#include "../target/target-addr.h"

/**
 * Output warning level at least in default
 */
/*no prefix added auto and will be print in default*/
#define LEVEL_OUT    (-3)
#define LEVEL_HINT   (-2)
#define LEVEL_ERROR  (-1)
#define LEVEL_WARN   (0)
#define LEVEL_INFO   (1)
#define LEVEL_DEBUG  (2)
#define LEVEL_DETAIL (3)

/**
 * Use logger after inited.
 */
void LOG_init();

/**
 * set if use ansi control characters.
 * !not thread safe, set it at early first.
 */
void LOG_set_ansi(bool no_ansi);

void LOG_close();

void LOG(int level, const char *fmt, ...);

void LOGip(int level, ipaddress ip, unsigned port, const char *fmt, ...);

void LOGnet(ipaddress ip_them, unsigned port_them, const char *fmt, ...);

int LOGopenssl(int level);

void LOG_add_level(int level);

int LOG_get_level();

#endif

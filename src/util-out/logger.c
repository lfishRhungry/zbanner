#include "logger.h"
#include "../util-data/safe-string.h"
#include <stdarg.h>
#include <stdio.h>

#ifndef NOT_FOUND_OPENSSL
#include <openssl/err.h>
#endif

static int _debug_level = 0;

/***************************************************************************
 ***************************************************************************/
void LOG_add_level(int x)
{
    _debug_level += x;
}

/***************************************************************************
 ***************************************************************************/
int LOG_get_level()
{
    return _debug_level;
}

/***************************************************************************
 ***************************************************************************/
static void
_vLOG(int level, const char *fmt, va_list marker)
{
    if (level <= _debug_level) {
        vfprintf(stderr, fmt, marker);
        fflush(stderr);
    }
}

/***************************************************************************
 ***************************************************************************/
void
LOG(int level, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    _vLOG(level, fmt, marker);
    va_end(marker);
}

/***************************************************************************
 ***************************************************************************/
static void
_vLOGnet(unsigned port_me, ipaddress ip_them, const char *fmt, va_list marker)
{
    char sz_ip[64];
    ipaddress_formatted_t fmt1 = ipaddress_fmt(ip_them);

    snprintf(sz_ip, sizeof(sz_ip), "%s", fmt1.string);
    if (ip_them.version==4) {
        fprintf(stderr, "%u:%s: ", port_me, sz_ip);
    } else {
        fprintf(stderr, "%u:[%s]: ", port_me, sz_ip);
    }
    vfprintf(stderr, fmt, marker);
    fflush(stderr);
}

void
LOGnet(unsigned port_me, ipaddress ip_them, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    _vLOGnet(port_me, ip_them, fmt, marker);
    va_end(marker);
}

/***************************************************************************
 ***************************************************************************/
static void
_vLOGip(int level, ipaddress ip, unsigned port, const char *fmt, va_list marker)
{
    if (level <= _debug_level) {
        char sz_ip[64];
        ipaddress_formatted_t fmt1 = ipaddress_fmt(ip);

        if (ip.version==4) {
            snprintf(sz_ip, sizeof(sz_ip), "%s:%u: ", fmt1.string, port);
        } else {
            snprintf(sz_ip, sizeof(sz_ip), "[%s]:%u: ", fmt1.string, port);
        }
        fprintf(stderr, "%s ", sz_ip);
        vfprintf(stderr, fmt, marker);
        fflush(stderr);
    }
}

/***************************************************************************
 ***************************************************************************/
void
LOGip(int level, ipaddress ip, unsigned port, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    _vLOGip(level, ip, port, fmt, marker);
    va_end(marker);
}

#ifndef NOT_FOUND_OPENSSL

/***************************************************************************
 ***************************************************************************/
static int
_LOGopenssl_cb(const char *str, size_t len, void *bp) {
  if (len > INT16_MAX) {
    return -1;
  }
  fprintf(stderr, "%.*s", (int)len, str);
  return 1;
}

/***************************************************************************
 ***************************************************************************/
int
LOGopenssl(int level) {
  int res = 0;
  if (level <= _debug_level) {
    fprintf(stderr, "[TSP OpenSSL error] ");
    ERR_print_errors_cb(_LOGopenssl_cb, NULL);
    // fprintf(stderr, "\n");
    fflush(stderr);
  }
  return res;
}

#endif
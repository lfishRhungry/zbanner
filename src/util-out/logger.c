#include "logger.h"
#include "../util-data/safe-string.h"
#include "../pixie/pixie-threads.h"

#include <stdarg.h>
#include <stdio.h>

#ifndef NOT_FOUND_OPENSSL
#include <openssl/err.h>
#endif

#define PREFIX_OUT       ""
#define PREFIX_HINT      "[-] "
#define PREFIX_ERROR     "[!] "
#define PREFIX_WARN      "[~] "
#define PREFIX_INFO      "[=] "
#define PREFIX_DEBUG     "[>] "
#define PREFIX_DETAIL    "[#] "

static int   _debug_level = 0;
static void *_log_mutex   = NULL;

/***************************************************************************
 ***************************************************************************/
static const char *
_level_to_string(int level)
{
    switch (level) {
        case LEVEL_OUT    : return PREFIX_OUT;
        case LEVEL_HINT   : return PREFIX_HINT;
        case LEVEL_ERROR  : return PREFIX_ERROR;
        case LEVEL_WARN   : return PREFIX_WARN;
        case LEVEL_INFO   : return PREFIX_INFO;
        case LEVEL_DEBUG  : return PREFIX_DEBUG;
        case LEVEL_DETAIL : return PREFIX_DETAIL;
        default:
            return "[?]";
    }
}

/***************************************************************************
 ***************************************************************************/
void LOG_init()
{
    if (_log_mutex) {
        pixie_delete_mutex(_log_mutex);
    }
    _log_mutex = pixie_create_mutex();
}

/***************************************************************************
 ***************************************************************************/
void LOG_close()
{
    if (_log_mutex) {
        pixie_delete_mutex(_log_mutex);
    }
    _log_mutex = NULL;
}

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
        pixie_acquire_mutex(_log_mutex);

        fputs(_level_to_string(level), stderr);
        vfprintf(stderr, fmt, marker);
        fflush(stderr);

        pixie_release_mutex(_log_mutex);
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
_vLOGnet(ipaddress ip_them, unsigned port_them, const char *fmt, va_list marker)
{
    ipaddress_formatted_t fmt1 = ipaddress_fmt(ip_them);

    pixie_acquire_mutex(_log_mutex);

    if (ip_them.version==4) {
        fprintf(stderr, "[Net](%s:%u) ", fmt1.string, port_them);
    } else {
        fprintf(stderr, "[Net]([%s]:%u) ", fmt1.string, port_them);
    }
    vfprintf(stderr, fmt, marker);
    fflush(stderr);

    pixie_release_mutex(_log_mutex);
}

void
LOGnet(ipaddress ip_them, unsigned port_them, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    _vLOGnet(ip_them, port_them, fmt, marker);
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

        pixie_acquire_mutex(_log_mutex);

        fputs(_level_to_string(level), stderr);
        if (ip.version==4) {
            snprintf(sz_ip, sizeof(sz_ip), "(%s:%u) ", fmt1.string, port);
        } else {
            snprintf(sz_ip, sizeof(sz_ip), "([%s]:%u) ", fmt1.string, port);
        }
        fprintf(stderr, "%s ", sz_ip);
        vfprintf(stderr, fmt, marker);
        fflush(stderr);

        pixie_release_mutex(_log_mutex);
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
      fputs("Error string is too long\n", stderr);
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
        pixie_acquire_mutex(_log_mutex);

        fputs(_level_to_string(level), stderr);
        fprintf(stderr, "(OpenSSL) ");
        ERR_print_errors_cb(_LOGopenssl_cb, NULL);
        fflush(stderr);

        pixie_release_mutex(_log_mutex);
    }
    return res;
}

#endif
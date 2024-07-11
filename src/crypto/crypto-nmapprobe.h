#ifndef CRYPTO_NMAPPROBE_H
#define CRYPTO_NMAPPROBE_H

/**
 * Nmap probe format is a half-hex like and allows escaped string. It is
 * convenient for record of probe data and tells us what to send.
 *
 * It is formatted similarly to a C or Perl string in that it allows the
 * following standard escape characters:
 * \\ \0, \a, \b, \f, \n, \r, \t, \v, and \xHH (where H is any hexadecimal
 * digit).
 *
 * NOTE: Originally, it must start with a q, then a delimiter character which
 * begins and ends the string. Between the delimiter characters is the string
 * that is actually sent. But the `q` and delimiters are not necessary here.
 */

#include "../util-misc/cross.h"
#include <stdlib.h>

/**
 * nmapprobe_decode - Unpack a hex string in nmap probe format.
 * It allows escape characters and hex like:
 *     \x05\x04\x00\x01\x02\x80\x05\x01\x00\x03\x0agoogle.com\x00\x50GET /
 * HTTP/1.0\r\n\r\n
 * @str: the string in nmap probe format (without `q` and delimiters)
 * @slen: the length of @str
 * @buf: the buffer to write the data into and its size cannot less than @slen
 * @bufsize: the length of @buf
 *
 * Returns len of decoded data.
 */
size_t nmapprobe_decode(const char *str, size_t slen, void *buf,
                        size_t bufsize);

#endif
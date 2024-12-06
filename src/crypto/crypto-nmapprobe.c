#include "crypto-nmapprobe.h"

#include <ctype.h>

#include "../util-out/logger.h"

/*****************************************************************************
 *****************************************************************************/
static int _is_hexchar(int c) {
    switch (c) {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            return 1;
        default:
            return 0;
    }
}

/*****************************************************************************
 *****************************************************************************/
static unsigned _hexval(int c) {
    switch (c) {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            return c - '0';
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            return c - 'a' + 10;
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            return c - 'A' + 10;
        default:
            return (unsigned)~0;
    }
}

/*****************************************************************************
 *****************************************************************************/
size_t nmapprobe_decode(const char *str, size_t slen, void *buf,
                        size_t bufsize) {
    char  *x        = buf;
    size_t offset   = 0;
    size_t x_offset = 0;

    while (offset < slen && x_offset < bufsize) {
        /* Normal case: unescaped characters */
        if (str[offset] != '\\') {
            x[x_offset++] = str[offset++];
            continue;
        }

        /* skip escape character '\\' */
        offset++;
        if (offset >= slen) {
            LOG(LEVEL_ERROR, "premature end of field\n");
            return 0;
        }

        /* Handled escape sequence */
        switch (str[offset++]) {
            default:
                LOG(LEVEL_ERROR, "unexpected escape character '%c'\n",
                    isprint(str[offset - 1]) ? str[offset - 1] : '.');
                return 0;
            case '\\':
                x[x_offset++] = '\\';
                break;
            case '0':
                x[x_offset++] = '\0';
                break;
            case 'a':
                x[x_offset++] = '\a';
                break;
            case 'b':
                x[x_offset++] = '\b';
                break;
            case 'f':
                x[x_offset++] = '\f';
                break;
            case 'n':
                x[x_offset++] = '\n';
                break;
            case 'r':
                x[x_offset++] = '\r';
                break;
            case 't':
                x[x_offset++] = '\t';
                break;
            case 'v':
                x[x_offset++] = '\v';
                break;
            case 'x':
                /* make sure at least 2 characters exist in input, either due
                 * to line-length or the delimiter */
                if (offset + 2 >= slen) {
                    LOG(LEVEL_ERROR, "line too short\n");
                    return 0;
                }

                /* make sure those two characters are hex digits */
                if (!_is_hexchar(str[offset + 0]) ||
                    !_is_hexchar(str[offset + 1])) {
                    LOG(LEVEL_ERROR, "expected hex, found '%c%c'\n",
                        isprint(str[offset + 1]) ? str[offset + 1] : '.',
                        isprint(str[offset + 2]) ? str[offset + 2] : '.');
                    return 0;
                }

                /* parse those two hex digits */
                x[x_offset++] = (char)(_hexval(str[offset + 0]) << 4 |
                                       _hexval(str[offset + 1]));
                offset += 2;
                break;
        }
    }

    return x_offset;
}
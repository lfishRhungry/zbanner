/*
 This module edits an existing TCP packet, adding and removing
 options, setting the values of certain fields.

 From RFC793:

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |          Source Port          |       Destination Port        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                        Sequence Number                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Acknowledgment Number                      |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Data |           |U|A|P|R|S|F|                               |
 | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 |       |           |G|K|H|T|N|N|                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           Checksum            |         Urgent Pointer        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Options                    |    Padding    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                             data                              |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 TCP Window Scale Option (WSopt):
 Kind: 3 Length: 3 bytes
 +---------+---------+---------+
 | Kind=3  |Length=3 |shift.cnt|
 +---------+---------+---------+

 TCP Timestamps Option (TSopt):
 Kind: 8
 Length: 10 bytes
 +-------+-------+---------------------+---------------------+
 |Kind=8 |  10   |   TS Value (TSval)  |TS Echo Reply (TSecr)|
 +-------+-------+---------------------+---------------------+
 1       1              4                     4

 TCP Sack-Permitted Option:
 Kind: 4
 +---------+---------+
 | Kind=4  | Length=2|
 +---------+---------+


 TCP SACK Option:
 Kind: 5
 Length: Variable

 +--------+--------+
 | Kind=5 | Length |
 +--------+--------+--------+--------+
 |      Left Edge of 1st Block       |
 +--------+--------+--------+--------+
 |      Right Edge of 1st Block      |
 +--------+--------+--------+--------+
 |                                   |
 /            . . .                  /
 |                                   |
 +--------+--------+--------+--------+
 |      Left Edge of nth Block       |
 +--------+--------+--------+--------+
 |      Right Edge of nth Block      |
 +--------+--------+--------+--------+


TCP pseudo header

                     +--------+--------+--------+--------+
                     |           Source Address          |
                     +--------+--------+--------+--------+
                     |         Destination Address       |
                     +--------+--------+--------+--------+
                     |  zero  |  PTCL  |    TCP Length   |
                     +--------+--------+--------+--------+
 */
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "templ-tcp.h"
#include "templ-opts.h"
#include "../globals.h"
#include "../util-out/logger.h"
#include "../util-misc/checksum.h"
#include "../util-data/safe-string.h"
#include "../util-data/data-convert.h"
#include "../proto/proto-preprocess.h"

struct tcp_opt_t {
    const unsigned char *buf;
    size_t length;
    unsigned kind;
    bool is_found;
};

struct tcp_hdr_t {
    size_t begin;
    size_t max;
    size_t ip_offset;
    unsigned char ip_version;
    bool is_found;
};

/***************************************************************************
 * A quick macro to calculate the TCP header length, given a buffer
 * and an offset to the start of the TCP header.
 ***************************************************************************/
static unsigned inline
_tcp_header_length(const unsigned char *buf, size_t offset) {
    return (buf[offset + 12] >> 4) * 4;
}

bool
tcp_consistancy_check(const unsigned char *buf, size_t length,
    const void *payload, size_t payload_length)
{
    struct PreprocessedInfo parsed;
    unsigned is_success;

    /* Parse the packet */
    is_success = preprocess_frame(buf,
                                  (unsigned)length,
                                  1 /*enet*/,
                                  &parsed);
    if (!is_success || parsed.found != FOUND_TCP) {
        fprintf(stderr, "[-] check: TCP header not found\n");
        goto fail;
    }

    /* Check the lengths */
    switch (parsed.ip_version) {
        case 4:
            if (parsed.ip_length + 14 != length) {
                fprintf(stderr, "[-] check: IP length bad\n");
                goto fail;
            }
            break;
        case 6:
            break;
        default:
            fprintf(stderr, "[-] check: IPv?\n");
            goto fail;
    }

    /* Validate TCP header options */
    {
        size_t offset = parsed.transport_offset;
        size_t max    = offset + _tcp_header_length(buf, offset);

        /* Get the start of the <options> section of the header. This is defined
         * as 20 bytes into the TCP header. */
        offset += 20;

        /* Enumerate any existing options one-by-one.  */
        while (offset < max) {
            unsigned kind;
            unsigned len;

            /* Get the option type (aka. "kind") */
            kind = buf[offset++];

            if (kind == 0x00) {
                /* EOL - end of options list
                 * According to the spec, processing should stop here, even if
                 * there are additional options after this point. */
                break;
            } else if (kind == 0x01) {
                /* NOP - No-operation
                 * This is a single byte option, used to pad other options to
                 * even 4 byte boundaries. Padding is optional. */
                continue;
            }

            /* If we've reached the end of */
            if (offset > max)
                goto fail;
            if (offset == max)
                break;
            len = buf[offset++];

            /* Check for corruption, the lenth field is inclusive, so should
             * equal at least two. It's maximum length should be bfore the end
             * of the packet */
            if (len < 2 || len > (max-offset+2)) {
                goto fail;
            }

            offset += len - 2;
        }
    }

    /* Check the payload */
    if (parsed.app_length != payload_length)
        goto fail;
    if (memcmp(buf + parsed.app_offset, payload, payload_length) != 0)
        goto fail;

    return false;
fail:
    return true;
}

/***************************************************************************
 * Find the TCP header in the packet. We can't be sure what's in the
 * current template because it could've been provided by the user, so
 * we instead parse it as if we've received it from the network wire.
 ***************************************************************************/
static struct tcp_hdr_t
_find_tcp_header(const unsigned char *buf, size_t length) {
    struct tcp_hdr_t hdr = {0};
    struct PreprocessedInfo parsed;
    unsigned is_success;

    /*
     * Parse the packet, telling us where the TCP header is. This works
     * for both IPv4 and IPv6, we care only about the TCP header portion.
     */
    is_success = preprocess_frame(buf, /* the packet, including Ethernet hdr */
                                  (unsigned)length,
                                  1 /*enet*/,
                                  &parsed);
    if (!is_success || parsed.found != FOUND_TCP) {
        /* We were unable to parse a well-formatted TCP packet. This
         * might've been UDP or something. */
        goto fail;
    }

    hdr.begin      = parsed.transport_offset;
    hdr.max        = hdr.begin + _tcp_header_length(buf, hdr.begin);
    hdr.ip_offset  = parsed.ip_offset;
    hdr.ip_version = (unsigned char)parsed.ip_version;
    hdr.is_found   = true;
    return hdr;

fail:
    hdr.is_found = false;
    return hdr;
}

/***************************************************************************
 * A quick macro at the start of for(;;) loops that enumerate all the
 * options in the <option-list>
 ***************************************************************************/
static inline size_t
_opt_begin(struct tcp_hdr_t hdr) {
    return hdr.begin + 20; /* start of <options> field */
}

/***************************************************************************
 * A quick macro in the for(;;) loop that enumerates all the options
 * in the <option-list>. It has three possibilities based on the KIND:
 * 0x00 - we've reached the end of the options-list
 * 0x01 - padding NOP byte, which we skipo
 * 0x?? - some option, the following byte is the length. We skip
 *        that `len` bytes.
 ***************************************************************************/
static inline size_t
_opt_next(struct tcp_hdr_t hdr, size_t offset, const unsigned char *buf) {
    unsigned kind = buf[offset];
    if (kind == 0x00) {
        return hdr.max;
    } else if (kind == 0x01) {
        return offset + 1;
    } else if (offset + 2 > hdr.max) {
        return hdr.max; /* corruption */
    } else {
        unsigned len = buf[offset+1];
        if (len < 2 || offset + len > hdr.max)
            return hdr.max; /* corruption */
        else
            return offset + len;
    }
}


/***************************************************************************
 * Search throgh the <option-list> until we find the specified option,
 * 'kind', or reach the end of the list. An impossible 'kind', like 0x100,
 * will force finding the end of the list before padding starts.
 ***************************************************************************/
static size_t
_find_opt(const unsigned char *buf, struct tcp_hdr_t hdr, unsigned in_kind,
          unsigned *nop_count) {
    size_t offset;

    /* This field is optional, if used, set it to zero */
    if (nop_count)
        *nop_count = 0;

    /* enumerate all <options> looking for a match */
    for (offset = _opt_begin(hdr);
         offset < hdr.max;
         offset = _opt_next(hdr, offset, buf)) {
        unsigned kind;

        /* get the option type/kind */
        kind = buf[offset];

        /* Stop search if we hit an EOL marker */
        if (kind == 0x00)
            break;

        /* Stop search when we find our option */
        if (kind == in_kind)
            break;

        /* Count the number of NOPs leading up to where we end */
        if (nop_count) {
            if (kind == 0x01)
                (*nop_count)++;
            else
                (*nop_count) = 0;
        }
    }
    return offset;
}

/***************************************************************************
 * Search the TCP header's <options> field for the specified kind/type.
 * Typical kinds of options are MSS, window scale, SACK, timestamp.
 ***************************************************************************/
static struct tcp_opt_t
tcp_find_opt(const unsigned char *buf, size_t length, unsigned in_kind) {
    struct tcp_opt_t result = {0};
    struct tcp_hdr_t hdr;
    size_t offset;

    /* Get the TCP header in the packet */
    hdr = _find_tcp_header(buf, length);
    if (!hdr.is_found)
        goto fail;

    /* Search for a matchin <option> */
    offset = _find_opt(buf, hdr, in_kind, 0);
    if (offset >= hdr.max || buf[offset] != in_kind)
        goto fail;

    /* We've found it! If we've passed all the checks above, we have
     * a well formatted field, so just return it. */
    result.kind   = in_kind;
    result.buf    = buf + offset + 2;
    result.length = buf[offset+1] - 2;
    if (offset + result.length >= hdr.max)
        goto fail;
    result.is_found = true;
    return result;

fail:
    result.is_found = false;
    return result;
}

/***************************************************************************
 * Adjusts the IP "total length" and TCP "header length" fields to match
 * recent additions/removals of options in the <option-list>
 ***************************************************************************/
static void
_adjust_length(unsigned char *buf, size_t length, int adjustment, struct tcp_hdr_t hdr) {
    size_t ip_offset = hdr.ip_offset;

    /* The adjustment should already have been aligned on an even 4 byte
     * boundary */
    if ((adjustment & 0x3) != 0) {
        fprintf(stderr, "[-] templ.tcp: impossible alignment error\n");
        return;
    }

    /* Adjust the IP header length */
    switch (hdr.ip_version) {
        case 4: {
            unsigned total_length;
            total_length  = BE_TO_U16(buf+ip_offset+2);
            total_length += adjustment;
            U16_TO_BE(buf+ip_offset+2, total_length);
            total_length  = BE_TO_U16(buf+ip_offset+2);
            if (total_length + 14 != length) {
                fprintf(stderr, "[-] IP length mismatch\n");
            }
            break;
        }
        case 6: {
            unsigned payload_length;
            payload_length  = BE_TO_U16(buf+ip_offset+4);
            payload_length += adjustment;
            U16_TO_BE(buf+ip_offset+4, payload_length);
            break;
        }
    }

    /* Adjust the TCP header length */
    {
        size_t hdr_length;
        size_t offset = hdr.begin + 12;

        hdr_length  = (buf[offset] >> 4) * 4;
        hdr_length += adjustment;

        if (hdr_length % 4 != 0) {
            fprintf(stderr, "[-] templ.tcp corruptoin\n");
        }

        buf[offset] = (unsigned char)((buf[offset] & 0x0F) | ((hdr_length/4) << 4));

        hdr_length = (buf[offset] >> 4) * 4;
        if (hdr.begin + hdr_length > length) {
            fprintf(stderr, "[-] templ.tcp corruptoin\n");
        }
    }
}

/***************************************************************************
 * After adding/removing an option, the <option-list> may no longer be
 * aligned on an even 4-byte boundary as required. This function
 * adds padding as necessary to align to the boundary.
 ***************************************************************************/
static void
_add_padding(unsigned char **inout_buf, size_t *inout_length, size_t offset, unsigned pad_count) {
    unsigned char *buf = *inout_buf;
    size_t length = *inout_length;

    length += pad_count;
    buf = realloc(buf, length);

    /* open space between headers and payload */
    safe_memmove(buf, length,
                offset + pad_count,
                offset,
                (length - pad_count) - offset);

    /* set padding to zero */
    safe_memset(buf, length,
                offset, 0, pad_count);

    /* Set the out parameters */
    *inout_buf = buf;
    *inout_length = length;
}

/***************************************************************************
 * After changes, there may be more padding bytes than necessary. This
 * reduces the number to 3 or less. Also, it changes any trailing NOPs
 * to EOL bytes, since there are no more options after that point.
 ***************************************************************************/
static bool
_normalize_padding(unsigned char **inout_buf, size_t *inout_length) {
    unsigned char     *buf         = *inout_buf;
    size_t             length      = *inout_length;
    unsigned           nop_count   = 0;
    size_t             offset;
    struct tcp_hdr_t   hdr;

    /* find TCP header */
    hdr = _find_tcp_header(buf, length);
    if (!hdr.is_found)
        goto fail;


    /* find the start of the padding field  */
    offset = _find_opt(buf, hdr, 0x100, &nop_count);
    if (offset >= hdr.max && nop_count == 0)
        goto success; /* no padding needing to be removed */

    /* If NOPs immediately before EOL, include them too */
    offset -= nop_count;

    {
        size_t remove_count = hdr.max - offset;

        /* the amount removed must be aligned on 4-byte boundary */
        while (remove_count % 4)
            remove_count--;

        /* If we have nothing left to remove, then exit.
         * THIS IS THE NORMAL CASE -- most of the time, we have no
         * extra padding to remove. */
        if (remove_count == 0)
            goto fail; /* likely, normal*/

        //_HEXDUMP(buf, hdr, offset, "before padding removal");

        safe_memmove(buf, length,
                        offset,
                        offset + remove_count,
                        length - (offset + remove_count));
        hdr.max -= remove_count;
        length -= remove_count;

        /* normalize all the bytes to zero, in case they aren't already */
        safe_memset(buf, length, offset, 0, hdr.max - offset);

        //_HEXDUMP(buf, hdr, offset, "after padding removal");

        /* fix the IP and TCP length fields */
        _adjust_length(buf, length, 0 - (int)remove_count, hdr);
    }

success:
    *inout_buf    = buf;
    *inout_length = length;
    return true; /* success */
fail:
    *inout_buf    = buf;
    *inout_length = length;
    return false; /* failure */

}


/***************************************************************************
 ***************************************************************************/
static bool
tcp_remove_opt(
        unsigned char **inout_buf, size_t *inout_length, unsigned in_kind
               ) {
    unsigned char      *buf         = *inout_buf;
    size_t              length      = *inout_length;
    unsigned            nop_count   = 0;
    size_t              offset;
    struct tcp_hdr_t    hdr;

    /* find the TCP header */
    hdr = _find_tcp_header(buf, length);
    if (!hdr.is_found)
        goto fail;

    /* enumerate all the <options> looking for a match  */
    offset = _find_opt(buf, hdr, in_kind, &nop_count);
    if (offset + 2 >= hdr.max)
        goto success; /* not found, no matching option type/kind */


    {
        unsigned opt_len       = buf[offset+1];
        unsigned remove_length = opt_len;

        if (offset + opt_len > hdr.max)
            goto fail;

        /* Remove any trailing NOPs */
        while (offset + remove_length < hdr.max
               && buf[offset + remove_length] == 1)
            remove_length++;

        /* Remove any leading NOPs */
        offset        -= nop_count;
        remove_length += nop_count;

        /* Remove the bytes from the current packet buffer.
         * Before this will be the ...IP/TCP headers plus maybe some options.
         * After this will be maybe some options, padding, then the TCP payload
         * */

        //_HEXDUMP(buf, hdr, offset, "before removal");

        safe_memmove(buf, length,
                        offset,
                        offset + remove_length,
                        length - (offset + remove_length));
        hdr.max -= remove_length;
        length  -= remove_length;

        //_HEXDUMP(buf, hdr, offset, "after removal");


        /* Now we may need to add back padding  */
        if (remove_length % 4) {
            unsigned add_length = (remove_length % 4);
            _add_padding(&buf, &length, hdr.max, add_length);
            remove_length -= add_length;
            hdr.max       += add_length;
        }

        //_HEXDUMP(buf, hdr, offset, "padding added");

        /* fix the IP and TCP length fields */
        _adjust_length(buf, length, 0 - remove_length, hdr);

        /* In case we've padded the packet with four 0x00, get rid
         * of them */
        _normalize_padding(&buf, &length);
    }

success:
    *inout_buf    = buf;
    *inout_length = length;
    return true;

fail:
    *inout_buf    = buf;
    *inout_length = length;
    return false;
}

/***************************************************************************
 ***************************************************************************/
static int
_insert_field(unsigned char **inout_buf,
              size_t *inout_length,
              size_t offset_begin,
              size_t offset_end,
              const unsigned char *new_data,
              size_t new_length
              ) {
    unsigned char *buf       = *inout_buf;
    size_t         length    = *inout_length;
    int            adjust    = 0;

    /* can theoreitcally be negative, but that's ok */
    adjust = (int)new_length - ((int)offset_end - (int)offset_begin);
    if (adjust > 0) {
        length += adjust;
        buf     = realloc(buf, length);
        safe_memmove(buf, length,
                        offset_begin + new_length,
                        offset_end,
                        (length - adjust) - offset_end);
    }
    if (adjust < 0) {
        safe_memmove(buf, length,
                        offset_begin + new_length,
                        offset_end,
                        length - offset_end);
        length += adjust;
        buf     = realloc(buf, length);
    }

    /**/
    memcpy(buf + offset_begin,
           new_data,
           new_length);

    *inout_buf = buf;
    *inout_length = length;

    return adjust;
}

/** Calculate the total number of padding bytes, both NOPs in the middle
 * and EOLs at the end. We call this when there's not enough space for
 * another option, and we want to remove all the padding. */
#if 0
static unsigned
_calc_padding(const unsigned char *buf, struct tcp_hdr_t hdr) {
    size_t offset;
    unsigned result = 0;

    /* enumerate through all <option> fields */
    for (offset = _opt_begin(hdr);
         offset < hdr.max;
         offset = _opt_next(hdr, offset, buf)) {
        unsigned kind;

        /* Get the kind: 0=EOL, 1=NOP, 2=MSS, 3=Wscale, etc. */
        kind = buf[offset];

        /* If EOL, we end here, and all the remainder bytes are counted
         * as padding. */
        if (kind == 0) {
            result += (hdr.max - offset);
            break;
        }

        /* If a NOP, then this is a padding byte */
        if (kind == 1)
            result++;
    }

    return result;
}
#endif

/***************************************************************************
 * Remove all the padding bytes, and return an offset to the beginning
 * of the rest of the option field.
 ***************************************************************************/
static size_t
_squeeze_padding(unsigned char *buf, size_t length, struct tcp_hdr_t hdr, unsigned in_kind) {
    size_t offset;
    unsigned nop_count = 0;

    for (offset = _opt_begin(hdr);
         offset < hdr.max;
         offset = _opt_next(hdr, offset, buf)) {
        unsigned kind;
        unsigned len;

        //_HEXDUMP(buf, hdr, offset, "squeeze");

        /* Get the kind: 0=EOL, 1=NOP, 2=MSS, 3=Wscale, etc. */
        kind = buf[offset];

        /* If a NOP padding, simply count it until we reach something
         * more interesting */
        if (kind == 0x01) {
            nop_count++;
            continue;
        }

        /* If end of option list, any remaining padding bytes are added */
        if (kind == 0x00) {
            /* normalize the padding at the end */
            offset -= nop_count;
            safe_memset(buf, length, offset, 0, hdr.max - offset);

            //_HEXDUMP(buf, hdr, offset, "null");

            return offset;
        }

        /* If we match an existing field, all those bytes become padding */
        if (kind == in_kind) {
            len = buf[offset+1];
            safe_memset(buf, length, offset, 0x01, len);
            nop_count++;

            //_HEXDUMP(buf, hdr, offset, "VVVVV");

            continue;
        }

        if (nop_count == 0)
            continue; /*no squeezing needed */

        /* move this field backward overwriting NOPs */
        len = buf[offset+1];
        safe_memmove(buf, length,
                        offset - nop_count,
                        offset,
                        len);

        //_HEXDUMP(buf, hdr, offset - nop_count, "<<<<");

        /* now write NOPs where this field used to be */
        safe_memset(buf, length, 
                    offset + len - nop_count, 0x01, nop_count);

        //_HEXDUMP(buf, hdr, offset + len - nop_count, "!!!!!");

        /* reset the <offset> to the end of this relocated field */
        offset    -= nop_count;
        nop_count  = 0;
    }

    /* if we reach the end, then there were only NOPs at the end and no
     * EOL byte, so simply zero them out */
    safe_memset(buf, length, 
                offset - nop_count, 0x00, nop_count);
    offset -= nop_count;

    //_HEXDUMP(buf, hdr, offset, "");

    return offset;
}


/***************************************************************************
 ***************************************************************************/
static bool
tcp_add_opt(unsigned char **inout_buf,
            size_t *inout_length,
            unsigned opt_kind,
            unsigned opt_length,
            const unsigned char *opt_data) {
    unsigned char      *buf          = *inout_buf;
    size_t              length       = *inout_length;
    unsigned            nop_count    = 0;
    int                 adjust       = 0;
    size_t              offset;
    struct tcp_hdr_t    hdr;


    /* Check for corruption:
     * The maximum size of a TCP header is 60 bytes (0x0F * 4), and the
     * rest of the header takes up 20 bytes. The [kind,length] takes up
     * another 2 bytes. Thus, the max option length is 38 bytes */
    if (opt_length > 38) {
        fprintf(stderr, "[-] templ.tcp.add_opt: opt_len too large\n");
        goto fail;
    }


    /* find TCP header */
    hdr = _find_tcp_header(buf, length);
    if (!hdr.is_found)
        goto fail;

    /* enumerate all existing options looking match */
    offset = _find_opt(buf, hdr, opt_kind, &nop_count);

    {
        unsigned char new_field[64];
        size_t        new_length;
        size_t        old_begin;
        size_t        old_end;

        /* Create a well-formatted field that will be inserted */
        new_length   = 1 + 1 + opt_length;
        new_field[0] = (unsigned char)opt_kind;
        new_field[1] = (unsigned char)new_length;
        memcpy(new_field + 2, opt_data, opt_length);

        /* Calculate the begin/end of the existing field in the packet */
        old_begin = offset;
        if (old_begin >= hdr.max)
            old_end = hdr.max; /* will insert end of header */
        else if (buf[offset] == 0x00)
            old_end = hdr.max; /* will insert start of padding */
        else if (buf[offset] == opt_kind) { /* will replace old field */
            size_t len = buf[offset + 1];
            old_end    = offset + len;
        } else {
            fprintf(stderr, "[-] not possible i09670t\n");
            return false;
        }

        /* If the existing space is too small, try to expand it by
         * using neighboring (leading, trailing) NOPs */
        while ((old_end-old_begin) < new_length) {
            if (nop_count) {
                nop_count--;
                old_begin--;
            } else if (old_end < hdr.max && buf[old_end] == 0x01) {
                old_end++;
            } else
                break;
        }

        /* If the existing space is too small, and we are at the end,
         * and there's pading, then try to use the padding */
        if ((old_end-old_begin) < new_length) {
            if (old_end < hdr.max) {
                if (buf[old_end] == 0x00) {
                    /* normalize padding to all zeroes */
                    safe_memset(buf, length, old_end, 0, hdr.max - old_end);

                    while ((old_end-old_begin) < new_length) {
                        if (old_end >= hdr.max)
                            break;
                        old_end++;
                    }
                }
            }
        }

        /* Make sure we have enough space in the header */
        {
            static const size_t max_tcp_hdr = (0xF0>>4) * 4; /* 60 */
            size_t added = new_length - (old_end - old_begin);
            if (hdr.max + added > hdr.begin + max_tcp_hdr) {
                //unsigned total_padding = _calc_padding(buf, hdr);
                old_begin = _squeeze_padding(buf, length, hdr, opt_kind);
                old_end   = hdr.max;
            }
        }


        /* Now insert the option field into packet. This may change the
         * sizeof the packet. The amount changed is indicated by 'adjust' */
        adjust   = _insert_field(&buf, &length,
                                 old_begin, old_end,
                                 new_field, new_length);
        hdr.max += adjust;
    }

    if (adjust) {

        /* TCP headers have to be aligned to 4 byte boundaries, so we may need
         * to add padding of 0 at the end of the header to handle this */
        if (adjust % 4 && adjust > 0) {
            unsigned add_length = 4 - (adjust % 4);
            _add_padding(&buf, &length, hdr.max, add_length);
            hdr.max += add_length;
            adjust += add_length;
        } else if (adjust % 4 && adjust < 0) {
            unsigned add_length = 0 - (adjust % 4);

            //_HEXDUMP(buf, hdr, hdr.max, "pad before");
            _add_padding(&buf, &length, hdr.max, add_length);
            hdr.max += add_length;
            adjust  += add_length;

            //_HEXDUMP(buf, hdr, hdr.max, "pad after");
        }

        /* fix the IP and TCP length fields */
        _adjust_length(buf, length, adjust, hdr);

        /* In case we've padded the packet with four 0x00, get rid
         * of them */
        _normalize_padding(&buf, &length);
    }

    *inout_buf    = buf;
    *inout_length = length;
    return true;

fail:
    /* no changes were made */
    *inout_buf    = buf;
    *inout_length = length;
    return false;
}

/***************************************************************************
 ***************************************************************************/
unsigned
tcp_get_mss(const unsigned char *buf, size_t length, bool *is_found) {
    struct tcp_opt_t opt;
    unsigned result = 0;

    opt = tcp_find_opt(buf, length, 2 /* MSS */);
    if (is_found)
        *is_found = opt.is_found;
    if (!opt.is_found)
        return 0xFFFFffff;

    if (opt.length != 2) {
        /* corrupt */
        if (is_found)
            *is_found = false;
        return 0xFFFFffff;
    }

    result = opt.buf[0] << 8 | opt.buf[1];

    return result;
}

/***************************************************************************
 ***************************************************************************/
unsigned
tcp_get_wscale(const unsigned char *buf, size_t length, bool *is_found) {
    struct tcp_opt_t opt;
    unsigned result = 0;

    opt = tcp_find_opt(buf, length, 3 /* Wscale */);
    if (is_found)
        *is_found = opt.is_found;
    if (!opt.is_found)
        return 0xFFFFffff;

    if (opt.length != 1) {
        /* corrupt */
        if (is_found)
            *is_found = false;
        return 0xFFFFffff;
    }

    result = opt.buf[0];

    return result;
}

/***************************************************************************
 ***************************************************************************/
unsigned
tcp_get_sackperm(const unsigned char *buf, size_t length, bool *is_found) {
    struct tcp_opt_t opt;

    opt = tcp_find_opt(buf, length, 3 /* Wscale */);
    if (is_found)
        *is_found = opt.is_found;
    if (!opt.is_found)
        return 0xFFFFffff;

    if (opt.length != 1) {
        /* corrupt */
        if (is_found)
            *is_found = false;
        return 0xFFFFffff;
    }

    return 0;
}

/***************************************************************************
 * Called at the end of configuration, to change the TCP header template
 * according to configuration. For example, we might add a "sackperm" field,
 * or delete an "mss" field, or change the value of "mss".
 ***************************************************************************/
void
templ_tcp_apply_options(unsigned char **inout_buf, size_t *inout_length,
                  const struct TemplateOptions *templ_opts) {
    unsigned char *buf = *inout_buf;
    size_t length = *inout_length;

    if (templ_opts == NULL)
        return;

    /* --tcp-mss <num>
     * Sets maximum segment size */
    if (templ_opts->tcp.is_mss == Remove) {
        tcp_remove_opt(&buf, &length, 2 /* mss */);
    } else if (templ_opts->tcp.is_mss == Add) {
        unsigned char field[2];
        U16_TO_BE(field, templ_opts->tcp.mss);
        tcp_add_opt(&buf, &length, 2, 2, field);
    }

    /* --tcp-sackok
     * Sets option flag that permits selective acknowledgements */
    if (templ_opts->tcp.is_sackok == Remove) {
        tcp_remove_opt(&buf, &length, 4 /* sackok */);
    } else if (templ_opts->tcp.is_sackok == Add) {
        tcp_add_opt(&buf, &length, 4, 0, (const unsigned char*)"");
    }

    /* --tcp-wscale <num>
     * Sets window scale option  */
    if (templ_opts->tcp.is_wscale == Remove) {
        tcp_remove_opt(&buf, &length, 3 /* wscale */);
    } else if (templ_opts->tcp.is_wscale == Add) {
        unsigned char field[1];
        field[0] = (unsigned char)templ_opts->tcp.wscale;
        tcp_add_opt(&buf, &length, 3, 1, field);
    }

    /* --tcp-ts <num>
     * Timestamp */
    if (templ_opts->tcp.is_tsecho == Remove) {
        tcp_remove_opt(&buf, &length, 8 /* ts */);
    } else if (templ_opts->tcp.is_tsecho == Add) {
        unsigned char field[10] = {0};
        U32_TO_BE(field, templ_opts->tcp.tsecho);
        tcp_add_opt(&buf, &length, 8, 8, field);
    }


    *inout_buf    = buf;
    *inout_length = length;
}


/***************************************************************************
 ***************************************************************************/
void
tcp_set_window(unsigned char *px, size_t px_length, unsigned window)
{
    struct PreprocessedInfo parsed;
    unsigned                x;
    size_t                  offset;
    unsigned                xsum;

    /* Parse the frame looking for the TCP header */
    x = preprocess_frame(px, (unsigned)px_length, 1 /*enet*/, &parsed);
    if (!x || parsed.found == FOUND_NOTHING)
        return;
    if (parsed.ip_protocol != 6)
        return;
    offset = parsed.transport_offset;
    if (offset + 20 > px_length)
        return;


    /* set the new window */
#if 0
    xsum = px[offset + 16] << 8 | px[offset + 17];
    xsum = (~xsum)&0xFFFF;
    xsum += window & 0xFFFF;
    xsum -= px[offset + 14] << 8 | px[offset + 15];
    xsum = ((xsum)&0xFFFF) + (xsum >> 16);
    xsum = ((xsum)&0xFFFF) + (xsum >> 16);
    xsum = ((xsum)&0xFFFF) + (xsum >> 16);
    xsum = (~xsum)&0xFFFF;
#endif

    U16_TO_BE(px+offset+14, window);
    px[offset + 16] = (unsigned char)(0);
    px[offset + 17] = (unsigned char)(0);


    xsum = ~checksum_tcp(px, parsed.ip_offset, parsed.transport_offset,
        parsed.transport_length);

    U16_TO_BE(px+offset+16, xsum);
}

size_t
tcp_create_by_template(
        const struct TemplatePacket *tmpl,
        ipaddress ip_them, unsigned port_them,
        ipaddress ip_me, unsigned port_me,
        unsigned seqno, unsigned ackno,
        unsigned flags,
        const unsigned char *payload, size_t payload_length,
        unsigned char *px, size_t px_length)
{
    if (tmpl->proto != Proto_TCP) {
            fprintf(stderr, "tcp_create_by_template: need a Proto_TCP TemplatePacket.\n");
            return 0;
    }

    uint64_t xsum;
  
    if (ip_them.version == 4) {
        unsigned ip_id = ip_them.ipv4 ^ port_them ^ seqno;
        unsigned offset_ip = tmpl->ipv4.offset_ip;
        unsigned offset_tcp = tmpl->ipv4. offset_tcp;
        unsigned offset_payload = offset_tcp + ((tmpl->ipv4.packet[offset_tcp+12]&0xF0)>>2);
        size_t new_length = offset_payload + payload_length;
        size_t ip_len = (offset_payload - offset_ip) + payload_length;
        unsigned old_len;

        if (new_length > px_length) {
            fprintf(stderr, "tcp: err generating packet: too much payload\n");
            return 0;
        }

        memcpy(px + 0, tmpl->ipv4.packet, tmpl->ipv4.length);
        memcpy(px + offset_payload, payload, payload_length);
        old_len = px[offset_ip+2]<<8 | px[offset_ip+3];

        /*
         * Fill in the empty fields in the IP header and then re-calculate
         * the checksum.
         */
        U16_TO_BE(px+offset_ip+ 2, ip_len);
        U16_TO_BE(px+offset_ip+ 4, ip_id);
        U32_TO_BE(px+offset_ip+12, ip_me.ipv4);
        U32_TO_BE(px+offset_ip+16, ip_them.ipv4);

        xsum  = tmpl->ipv4.checksum_ip;
        xsum += (ip_id&0xFFFF);
        xsum += ip_me.ipv4;
        xsum += ip_them.ipv4;
        xsum += ip_len - old_len;
        xsum  = (xsum >> 16) + (xsum & 0xFFFF);
        xsum  = (xsum >> 16) + (xsum & 0xFFFF);
        xsum  = ~xsum;

        U16_TO_BE(px+offset_ip+10, xsum);

        /*
         * now do the same for TCP
         */
        U16_TO_BE(px+offset_tcp+ 0, port_me);
        U16_TO_BE(px+offset_tcp+ 2, port_them);
        U32_TO_BE(px+offset_tcp+ 4, seqno);
        U32_TO_BE(px+offset_tcp+ 8, ackno);

        px[offset_tcp+13] = (unsigned char)flags;

        /*tcp window: we have set in the default template*/
        // px[offset_tcp+14] = (unsigned char)(1200>>8);
        // px[offset_tcp+15] = (unsigned char)(1200 & 0xFF);

        px[offset_tcp+16] = (unsigned char)(0 >>  8);
        px[offset_tcp+17] = (unsigned char)(0 >>  0);

        xsum = checksum_tcp(px, tmpl->ipv4.offset_ip, tmpl->ipv4.offset_tcp,
            new_length - tmpl->ipv4.offset_tcp);
        xsum = ~xsum;

        U16_TO_BE(px+offset_tcp+16, xsum);

        if (new_length < 60) {
            memset(px+new_length, 0, 60-new_length);
            new_length = 60;
        }
        return new_length;
    } else {
        unsigned offset_ip  = tmpl->ipv6.offset_ip;
        unsigned offset_tcp = tmpl->ipv6.offset_tcp;
        unsigned offset_app = tmpl->ipv6.offset_app;

        /* Make sure the new packet won't exceed buffer size */
        if (offset_app + payload_length > px_length) {
            fprintf(stderr, "tcp: err generating packet: too much payload\n");
            return 0;
        }

        /* Copy over everything up to the new application-layer-payload */
        memcpy(px, tmpl->ipv6.packet, tmpl->ipv6.offset_app);

        /* Replace the template's application-layer-payload with the new app-payload */
        memcpy(px + tmpl->ipv6.offset_app, payload, payload_length);

        /* Fixup the "payload length" field in the IPv6 header. This is everything
         * after the IPv6 header. There may be additional headers between the IPv6
         * and TCP headers, so the calculation isn't simply the length of the TCP portion */
        {
            size_t len = tmpl->ipv6.offset_app + payload_length - tmpl->ipv6.offset_ip - 40;
            U16_TO_BE(px+offset_ip+ 4, len);
        }

        /* Copy over the IP addresses */
        U64_TO_BE(px+offset_ip+ 8, ip_me.ipv6.hi);
        U64_TO_BE(px+offset_ip+16, ip_me.ipv6.lo);

        U64_TO_BE(px+offset_ip+24, ip_them.ipv6.hi);
        U64_TO_BE(px+offset_ip+32, ip_them.ipv6.lo);

        /*
         * now do the same for TCP
         */
        U16_TO_BE(px+offset_tcp+ 0, port_me);
        U16_TO_BE(px+offset_tcp+ 2, port_them);
        U32_TO_BE(px+offset_tcp+ 4, seqno);
        U32_TO_BE(px+offset_tcp+ 8, ackno);

        px[offset_tcp+13] = (unsigned char)flags;

        /*tcp window: we have set in the default template*/
        // px[offset_tcp+14] = (unsigned char)(1200>>8);
        // px[offset_tcp+15] = (unsigned char)(1200 & 0xFF);

        px[offset_tcp+16] = (unsigned char)(0 >>  8);
        px[offset_tcp+17] = (unsigned char)(0 >>  0);

        xsum = checksum_ipv6(px + offset_ip + 8, px + offset_ip + 24, 6, (offset_app - offset_tcp) + payload_length, px + offset_tcp);
        U16_TO_BE(px+offset_tcp+16, xsum);

        return offset_app + payload_length;
    }
}

size_t
tcp_create_packet(
        ipaddress ip_them, unsigned port_them,
        ipaddress ip_me, unsigned port_me,
        unsigned seqno, unsigned ackno,
        unsigned flags,
        const unsigned char *payload, size_t payload_length,
        unsigned char *px, size_t px_length)
{
    /*use different template for tcp with syn flags to apply some options*/
    if ((flags&TCP_FLAG_SYN)==TCP_FLAG_SYN) {
        return tcp_create_by_template(&global_tmplset->pkts[Proto_TCP_SYN],
            ip_them, port_them, ip_me, port_me,
            seqno, ackno, flags,
            payload, payload_length, px, px_length);
    } else {
        return tcp_create_by_template(&global_tmplset->pkts[Proto_TCP],
            ip_them, port_them, ip_me, port_me,
            seqno, ackno, flags,
            payload, payload_length, px, px_length);
    }
}

void
tcp_flags_to_string(unsigned flag, char *string, size_t str_len)
{
    snprintf(string, str_len, "%s%s%s%s%s%s%s%s",
            (flag&TCP_FLAG_FIN)?"fin-":"",
            (flag&TCP_FLAG_SYN)?"syn-":"",
            (flag&TCP_FLAG_RST)?"rst-":"",
            (flag&TCP_FLAG_PSH)?"psh-":"",
            (flag&TCP_FLAG_ACK)?"ack-":"",
            (flag&TCP_FLAG_URG)?"urg-":"",
            (flag&TCP_FLAG_ECE)?"ece-":"",
            (flag&TCP_FLAG_CWR)?"cwr-":""
            );
        if (string[0] == '\0')
            snprintf(string, str_len, "none");
        else
            string[strlen(string)-1] = '\0';
}
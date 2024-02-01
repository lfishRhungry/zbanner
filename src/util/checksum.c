/*
    Calculates Internet checksums for protocols like TCP/IP.

    Author: Robert David Graham
    Copyright: 2020
    License: The MIT License (MIT)
    Dependencies: none
*/
#include <stdint.h>

#include "checksum.h"

/**
 * Calculates the checksum over a buffer.
 * @param checksum
 *      The value of the pseudo-header checksum that this sum will be
 *      added to. This value must be calculated separately. This
 *      is the original value in 2s-complement. In other words,
 *      for TCP, which will be the integer value of the 
 *      IP addresses, protocol number, and length field added together.
 * @param buf
 *      The buffer that we are checksumming, such as all the
 *      payload after an IPv4 or IPv6 header.
 */
static unsigned
_checksum_calculate(const void *vbuf, size_t length)
{
    unsigned sum = 0;
    size_t i;
    const unsigned char *buf = (const unsigned char *)vbuf;
    int is_remainder;

    /* If there is an odd number of bytes, then we handle the 
     * last byte in a custom manner. */
    is_remainder = (length & 1);
    length &= (~1);

    /* Sum up all the 16-bit words in the packet */
    for (i=0; i<length; i += 2) {
        sum += buf[i]<<8 | buf[i+1];
    }

    /* If there is an odd number of bytes, then add the last
     * byte to the sum, in big-endian format as if there was
     * an additional trailing byte of zero. */
    if (is_remainder)
        sum += buf[length]<<8;

    /* Return the raw checksum. Note that this hasn't been
     * truncated to 16-bits yet or had the bits reversed. */
    return sum;
}


/**
 * After we sum up all the numbers involved, we must "fold" the upper
 * 16-bits back into the lower 16-bits. Since something like 0x1FFFF
 * will fold into 0x10000, we need to call a second fold operation
 * (obtaining 0x0001 in this example). In other words, we need to 
 * keep folding until the result is 16-bits, but that never takes
 * more than two folds. After this, we need to take the 1s-complement,
 * which means reversing the bits so that 0 becomes 1 and 1 becomes 0.
 */
static unsigned
_checksum_finish(unsigned sum)
{
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = (sum >> 16) + (sum & 0xFFFF);
    return (~sum) & 0xFFFF;
}


unsigned 
checksum_ipv4(unsigned ip_src, unsigned ip_dst,
    unsigned ip_proto, size_t payload_length, const void *payload)
{
    unsigned sum;
    const unsigned char *buf = (const unsigned char *)payload;

    /* Calculate the sum of the pseudo-header. Note that all these fields
     * are assumed to be in host byte-order, not big-endian */
    sum = (ip_src>>16) & 0xFFFF;
    sum += (ip_src>> 0) & 0xFFFF;
    sum += (ip_dst>>16) & 0xFFFF;
    sum += (ip_dst>> 0) & 0xFFFF;
    sum += ip_proto;
    sum += (unsigned)payload_length;
    sum += _checksum_calculate(buf, payload_length);

    /* Remove the existing checksum field from the calculation. */
    switch (ip_proto) {
    case 0: /* IP header -- has no pseudo header */
        sum = _checksum_calculate(buf, payload_length);
        sum -= buf[10]<<8 | buf[11]; /* pretend the existing checksum field is zero */
        break;
    case 1:
        sum -= buf[2]<<8 | buf[3];
        break;
    case 2: /* IGMP - group message - has no pseudo header */
        sum = _checksum_calculate(payload, payload_length);
        sum -= buf[2]<<8 | buf[3];
        break;
    case 6:
        sum -= buf[16]<<8 | buf[17];
        break;
    case 17:
        sum -= buf[6]<<8 | buf[7];
        break;
    default:
        return 0xFFFFFFFF;
    }

    sum = _checksum_finish(sum);
    return sum;
}

unsigned 
checksum_ipv6(const unsigned char *ip_src, const unsigned char *ip_dst, unsigned ip_proto, size_t payload_length, const void *payload)
{
    const unsigned char *buf = (const unsigned char *)payload;
    unsigned sum;

    /* Calculate the pseudo-header */
    sum = _checksum_calculate(ip_src, 16);
    sum += _checksum_calculate(ip_dst, 16);
    sum += (unsigned)payload_length;
    sum += ip_proto;

    /* Calculate the remainder of the checksum */
    sum += _checksum_calculate(payload, payload_length);

    /* Remove the existing checksum field. */
    switch (ip_proto) {
    case 0:
        return 0;
    case 1:
    case 58:
        sum -= buf[2]<<8 | buf[3];
        break;
    case 6:
        sum -= buf[16]<<8 | buf[17];
        break;
    case 17:
        sum -= buf[6]<<8 | buf[7];
        break;
    default:
        return 0xFFFFFFFF;
    }

    /* fold and invert */
    sum = _checksum_finish(sum);
    return sum;
}


/***************************************************************************
 * Checksum the IP header. This is a "partial" checksum, so we
 * don't reverse the bits ~.
 ***************************************************************************/
unsigned
checksum_ip_header(const unsigned char *px, unsigned offset, unsigned max_offset)
{
    unsigned header_length = (px[offset]&0xF) * 4;
    unsigned xsum = 0;
    unsigned i;

    /* restrict check only over packet */
    if (max_offset > offset + header_length)
        max_offset = offset + header_length;

    /* add all the two-byte words together */
    xsum = 0;
    for (i = offset; i < max_offset; i += 2) {
        xsum += px[i]<<8 | px[i+1];
    }

    /* if more than 16 bits in result, reduce to 16 bits */
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    return xsum;
}

/***************************************************************************
 ***************************************************************************/
unsigned
checksum_icmp(const unsigned char *px,
    unsigned offset_icmp, size_t icmp_length)
{
    uint64_t xsum = 0;
    unsigned i;

    for (i=0; i<icmp_length; i += 2) {
        xsum += px[offset_icmp + i]<<8 | px[offset_icmp + i + 1];
    }

    xsum -= (icmp_length & 1) * px[offset_icmp + i - 1]; /* yea I know going off end of packet is bad so sue me */
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    return (unsigned)xsum;
}

/***************************************************************************
 ***************************************************************************/
unsigned
checksum_udp(const unsigned char *px, unsigned offset_ip,
    unsigned offset_tcp, size_t tcp_length)
{
    uint64_t xsum = 0;
    unsigned i;

    /* pseudo checksum */
    xsum = 17;
    xsum += tcp_length;
    xsum += px[offset_ip + 12] << 8 | px[offset_ip + 13];
    xsum += px[offset_ip + 14] << 8 | px[offset_ip + 15];
    xsum += px[offset_ip + 16] << 8 | px[offset_ip + 17];
    xsum += px[offset_ip + 18] << 8 | px[offset_ip + 19];

    /* TCP checksum */
    for (i=0; i<tcp_length; i += 2) {
        xsum += px[offset_tcp + i]<<8 | px[offset_tcp + i + 1];
    }

    xsum -= (tcp_length & 1) * px[offset_tcp + i - 1]; /* yea I know going off end of packet is bad so sue me */
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    return (unsigned)xsum;
}

/***************************************************************************
 ***************************************************************************/
unsigned
checksum_tcp(const unsigned char *px, unsigned offset_ip,
    unsigned offset_tcp, size_t tcp_length)
{
    uint64_t xsum = 0;
    unsigned i;

    /* pseudo checksum */
    xsum = 6;
    xsum += tcp_length;
    xsum += px[offset_ip + 12] << 8 | px[offset_ip + 13];
    xsum += px[offset_ip + 14] << 8 | px[offset_ip + 15];
    xsum += px[offset_ip + 16] << 8 | px[offset_ip + 17];
    xsum += px[offset_ip + 18] << 8 | px[offset_ip + 19];

    /* TCP checksum */
    for (i=0; i<tcp_length; i += 2) {
        xsum += px[offset_tcp + i]<<8 | px[offset_tcp + i + 1];
    }

    xsum -= (tcp_length & 1) * px[offset_tcp + i - 1]; /* yea I know going off end of packet is bad so sue me */
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    return (unsigned)xsum;
}
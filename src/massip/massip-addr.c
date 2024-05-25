#include "massip-addr.h"
#include <string.h>


/**
 * Holds the output string, so that we can append to it without
 * overflowing buffers. The _append_xxx() functions below append
 * to this string.
 */
typedef struct stream_t {
    char *buf;
    size_t offset;
    size_t length;
} stream_t;

/**
 * Append a character to the output string. All the other _append_xxx()
 * functions call _append_char or _append_str, so they must do buffer-overflow
 * check.
 */
static void
_append_char(stream_t *out, char c)
{
    if (out->offset < out->length)
        out->buf[out->offset++] = c;

    /* keep the string nul terminated as we build it */
    if (out->offset < out->length)
        out->buf[out->offset] = '\0';
}

/**
 * Append a c string to the output string. All the other _append_xxx()
 * functions call _append_char or _append_str, so they must do buffer-overflow
 * check.
 */
static void
_append_str(stream_t *out, char *str)
{
    size_t len = strlen(str);

    for (size_t i=0;i<len;i++) {
        if (out->offset < out->length) {
            out->buf[out->offset++] = str[i];
        } else {
            break;
        }
    }

    /* keep the string nul terminated as we build it */
    if (out->offset < out->length)
        out->buf[out->offset] = '\0';
}

static void
_append_ipv6(stream_t *out, const unsigned char *ipv6)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    int is_ellision = 0;

    /* An IPv6 address is printed as a series of 2-byte hex words
     * separated by colons :, for a total of 16-bytes */
    for (i = 0; i < 16; i += 2) {
        unsigned n = ipv6[i] << 8 | ipv6[i + 1];

        /* Handle the ellision case. A series of words with a value
         * of 0 can be removed completely, replaced by an extra colon */
        if (n == 0 && !is_ellision) {
            is_ellision = 1;
            while (i < 13 && ipv6[i + 2] == 0 && ipv6[i + 3] == 0)
                i += 2;
            _append_char(out, ':');

            /* test for all-zero address, in which case the output
             * will be "::". */
            while (i == 14 && ipv6[i] == 0 && ipv6[i + 1] == 0){
                i=16;
                _append_char(out, ':');
            }
            continue;
        }

        /* Print the colon between numbers. Fence-post alert: only colons
         * between numbers are printed, not at the beginning or end of the
         * string */
        if (i)
            _append_char(out, ':');

        /* Print the digits. Leading zeroes are not printed */
        if (n >> 12)
            _append_char(out, hex[(n >> 12) & 0xF]);
        if (n >> 8)
            _append_char(out, hex[(n >> 8) & 0xF]);
        if (n >> 4)
            _append_char(out, hex[(n >> 4) & 0xF]);
        _append_char(out, hex[(n >> 0) & 0xF]);
    }
}

size_t ipv6_byte2str(const unsigned char *bytes, char *buf, size_t buf_len)
{
    stream_t s;
    /* Call the formatting function */
    s.buf = buf;
    s.offset = 0;
    s.length = buf_len;
    _append_ipv6(&s, bytes);

    return s.offset;
}

struct ipaddress_formatted ipv6address_fmt(ipv6address a)
{
    struct ipaddress_formatted out;
    unsigned char tmp[16];
    size_t i;
    stream_t s;

    /*
     * Convert address into a sequence of bytes. Our code
     * here represents an IPv6 address as two 64-bit numbers, but
     * the formatting code above that we copied from a different
     * project represents it as an array of bytes.
     */
    for (i=0; i<16; i++) {
        uint64_t x;
        if (i<8)
            x = a.hi;
        else
            x = a.lo;
        x >>= (7 - (i%8)) * 8;

        tmp[i] = (unsigned char)(x & 0xFF);
    }

    /* Call the formatting function */
    s.buf = out.string;
    s.offset = 0;
    s.length = sizeof(out.string);
    _append_ipv6(&s, tmp);

    return out;
}

/**
 * Append a decimal integer.
 */
static void
_append_decimal(stream_t *out, unsigned long long n)
{
    char tmp[64];
    size_t tmp_offset = 0;

    /* Create temporary string */
    while (n >= 10) {
        unsigned digit = n % 10;
        n /= 10;
        tmp[tmp_offset++] = (char)('0' + digit);
    }
    
    /* the final digit, may be zero */
    tmp[tmp_offset++] = (char)('0' + n);

    /* Copy the result backwards */
    while (tmp_offset)
        _append_char(out, tmp[--tmp_offset]);
}

static void
_append_hex2(stream_t *out, unsigned long long n)
{
    static const char hex[17] = "0123456789abcdef";
    
    _append_char(out, hex[(n>>4)&0xF]);
    _append_char(out, hex[(n>>0)&0xF]);
}

size_t ipv4_byte2str(const unsigned char *bytes, char *buf, size_t buf_len)
{
    stream_t s;
    /* Call the formatting function */
    s.buf = buf;
    s.offset = 0;
    s.length = buf_len;
    _append_decimal(&s, buf[0]);
    _append_char(&s, '.');
    _append_decimal(&s, buf[1]);
    _append_char(&s, '.');
    _append_decimal(&s, buf[2]);
    _append_char(&s, '.');
    _append_decimal(&s, buf[3]);

    return s.offset;
}

struct ipaddress_formatted ipv4address_fmt(ipv4address ip)
{
    struct ipaddress_formatted out;
    stream_t s;


    /* Call the formatting function */
    s.buf = out.string;
    s.offset = 0;
    s.length = sizeof(out.string);

    _append_decimal(&s, (ip >> 24) & 0xFF);
    _append_char(&s, '.');
    _append_decimal(&s, (ip >> 16) & 0xFF);
    _append_char(&s, '.');
    _append_decimal(&s, (ip >> 8) & 0xFF);
    _append_char(&s, '.');
    _append_decimal(&s, (ip >> 0) & 0xFF);

    return out;
}

struct ipaddress_formatted macaddress_fmt(macaddress_t mac)
{
    struct ipaddress_formatted out;
    stream_t s;


    /* Call the formatting function */
    s.buf = out.string;
    s.offset = 0;
    s.length = sizeof(out.string);

    _append_hex2(&s, mac.addr[0]);
    _append_char(&s, '-');
    _append_hex2(&s, mac.addr[1]);
    _append_char(&s, '-');
    _append_hex2(&s, mac.addr[2]);
    _append_char(&s, '-');
    _append_hex2(&s, mac.addr[3]);
    _append_char(&s, '-');
    _append_hex2(&s, mac.addr[4]);
    _append_char(&s, '-');
    _append_hex2(&s, mac.addr[5]);

    return out;
}

struct ipaddress_formatted ipaddress_fmt(ipaddress a)
{
    struct ipaddress_formatted out;
    stream_t s;
    ipv4address ip = a.ipv4;

    if (a.version == 6) {
        return ipv6address_fmt(a.ipv6);
    } else if (a.version == 4) {
        /* Call the formatting function */
        s.buf = out.string;
        s.offset = 0;
        s.length = sizeof(out.string);

        _append_decimal(&s, (ip >> 24) & 0xFF);
        _append_char(&s, '.');
        _append_decimal(&s, (ip >> 16) & 0xFF);
        _append_char(&s, '.');
        _append_decimal(&s, (ip >> 8) & 0xFF);
        _append_char(&s, '.');
        _append_decimal(&s, (ip >> 0) & 0xFF);
    } else {
        out.string[0] = '\0';
    }

    return out;
}

struct ipaddress_ptr ipv6address_ptr_fmt(ipv6address a)
{
    struct ipaddress_ptr out;
    stream_t s;

    s.buf = out.string;
    s.offset = 0;
    s.length = sizeof(out.string);

    static const char hex[17] = "0123456789abcdef";

    for (int i=15; i>=0; i--) {
        uint64_t x;
        if (i<8)
            x = a.hi;
        else
            x = a.lo;
        x >>= (7 - (i%8)) * 8;

        _append_char(&s, hex[(x>>0)&0xF]);
        _append_char(&s, '.');
        _append_char(&s, hex[(x>>4)&0xF]);
        _append_char(&s, '.');
    }

    _append_str(&s, "ip6.arpa");

    return out;
}

struct ipaddress_ptr ipv4address_ptr_fmt(ipv4address ip)
{
    struct ipaddress_ptr out;
    stream_t s;

    /* Call the formatting function */
    s.buf = out.string;
    s.offset = 0;
    s.length = sizeof(out.string);

    _append_decimal(&s, (ip >> 0) & 0xFF);
    _append_char(&s, '.');
    _append_decimal(&s, (ip >> 8) & 0xFF);
    _append_char(&s, '.');
    _append_decimal(&s, (ip >> 16) & 0xFF);
    _append_char(&s, '.');
    _append_decimal(&s, (ip >> 24) & 0xFF);
    _append_str(&s, ".in-addr.arpa");

    return out;
}

struct ipaddress_ptr ipaddress_ptr_fmt(ipaddress a)
{
    struct ipaddress_ptr out;
    stream_t s;
    ipv4address ip = a.ipv4;

    if (a.version == 6) {
        return ipv6address_ptr_fmt(a.ipv6);
    } else if (a.version == 4) {
        /* Call the formatting function */
        s.buf = out.string;
        s.offset = 0;
        s.length = sizeof(out.string);

        _append_decimal(&s, (ip >> 0) & 0xFF);
        _append_char(&s, '.');
        _append_decimal(&s, (ip >> 8) & 0xFF);
        _append_char(&s, '.');
        _append_decimal(&s, (ip >> 16) & 0xFF);
        _append_char(&s, '.');
        _append_decimal(&s, (ip >> 24) & 0xFF);
        _append_str(&s, ".in-addr.arpa");
    } else {
        out.string[0] = '\0';
    }


    return out;
}


static unsigned _count_long(uint64_t number)
{
    unsigned i;
    unsigned count = 0;
    for (i=0; i<64; i++) {
        if ((number >> i) & 1)
            count = i + 1;
    }
    return count;
}

/**
 * Find the number of bits needed to hold the integer. In other words,
 * the number 0x64 would need 7 bits to store it.
 *
 * We use this to count the size of scans. We currently only support
 * scan sizes up to 63 bits.
 */
unsigned massint128_bitcount(massint128_t number)
{
    if (number.hi)
        return _count_long(number.hi) + 64;
    else
        return _count_long(number.lo);
}

ipv6address_t ipv6address_add_uint64(ipv6address_t lhs, uint64_t rhs) {
    lhs.lo += rhs;
    if (lhs.lo < rhs) {
        lhs.hi += 1;
    }
    return lhs;
}

ipv6address_t ipv6address_subtract(ipv6address_t lhs, ipv6address_t rhs) {
    ipv6address_t difference;
    difference.hi = lhs.hi - rhs.hi;
    difference.lo = lhs.lo - rhs.lo;

    /* check for underflow */
    if (difference.lo > lhs.lo)
        difference.hi -= 1;
    return difference;
}

ipv6address_t ipv6address_add(ipv6address_t lhs, ipv6address_t rhs) {
    ipv6address_t sum;
    sum.hi = lhs.hi + rhs.hi;
    sum.lo = lhs.lo - rhs.lo;

    /* check for underflow */
    if (sum.lo > lhs.lo)
        sum.hi += 1;
    return sum;
}


bool ipv6address_is_equal_prefixed(ipv6address_t lhs, ipv6address_t rhs, unsigned prefix)
{
    ipv6address mask;
    
    /* If the prefix is bad, then the answer is 'no'. */
    if (prefix > 128) {
        return false;
    }

    /* Create the mask from the prefix */
    if (prefix > 64)
        mask.hi = ~0ULL;
    else if (prefix == 0)
        mask.hi = 0;
    else
        mask.hi = ~0ULL << (64 - prefix);
    
    if (prefix > 64)
        mask.lo = ~0ULL << (128 - prefix);
    else
        mask.lo = 0;

    /* Mask off any non-zero bits from both addresses */
    lhs.hi &= mask.hi;
    lhs.lo &= mask.lo;
    rhs.hi &= mask.hi;
    rhs.lo &= mask.lo;

    /* Now do a normal compare */
    return ipv6address_is_equal(lhs, rhs);
}

int ipv6address_selftest()
{
    int x = 0;
    ipaddress ip;
    struct ipaddress_formatted fmt;

    ip.version = 4;
    ip.ipv4 = 0x01FF00A3;

    fmt = ipaddress_fmt(ip);
    if (strcmp(fmt.string, "1.255.0.163") != 0)
        x++;

    return x;
}
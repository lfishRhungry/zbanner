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

#define CRC32C_POLY 0x1EDC6F41
#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF])

static unsigned crc_c[256] =
{
0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L,
};

unsigned
checksum_sctp(const void *vbuffer, size_t length)
{
    const unsigned char *buffer = (const unsigned char *)vbuffer;
    unsigned i;
    unsigned crc32 = (unsigned)~0;
    unsigned result;
    unsigned char byte0,byte1,byte2,byte3;

    for (i = 0; i < 8; i++) {
        CRC32C(crc32, buffer[i]);
    }

    CRC32C(crc32, 0);
    CRC32C(crc32, 0);
    CRC32C(crc32, 0);
    CRC32C(crc32, 0);

    for (i = 12; i < length; i++) {
        CRC32C(crc32, buffer[i]);
    }
    result = ~crc32;

    /*  result  now holds the negated polynomial remainder;
    *  since the table and algorithm is "reflected" [williams95].
    *  That is,  result has the same value as if we mapped the message
    *  to a polynomial, computed the host-bit-order polynomial
    *  remainder, performed final negation, then did an end-for-end
    *  bit-reversal.
    *  Note that a 32-bit bit-reversal is identical to four in-place
    *  8-bit reversals followed by an end-for-end byte swap.
    *  In other words, the bytes of each bit are in the right order,
    *  but the bytes have been byte swapped.  So we now do an explicit
    *  byte swap.  On a little-endian machine, this byte swap and
    *  the final ntohl cancel out and could be elided.
    */

    byte0 = result & 0xff;
    byte1 = (result>>8) & 0xff;
    byte2 = (result>>16) & 0xff;
    byte3 = (result>>24) & 0xff;

    crc32 = ((byte0 << 24) |
            (byte1 << 16) |
            (byte2 << 8)  |
            byte3);
    return ( crc32 );
}
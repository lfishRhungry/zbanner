#ifndef DATA_CONVERT_H
#define DATA_CONVERT_H

#include <stdint.h>

#if defined(_MSC_VER)
#define inline _inline
#endif

#define BE_TO_U16(px) (px)[0]<< 8|(px)[1]
#define BE_TO_U32(px) (px)[0]<<24|(px)[1]<<16|(px)[2]<< 8|(px)[3]
#define BE_TO_U64(px) (px)[0]<<56|(px)[1]<<48|(px)[2]<<40|(px)[3]<<32|(px)[4]<<24|(px)[5]<<16|(px)[6]<< 8|(px)[7]

#define LE_TO_U16(px) (px)[1]<< 8|(px)[0]
#define LE_TO_U32(px) (px)[3]<<24|(px)[2]<<16|(px)[1]<< 8|(px)[0]
#define LE_TO_U64(px) (px)[7]<<56|(px)[6]<<48|(px)[5]<<40|(px)[4]<<32|(px)[3]<<24|(px)[2]<<16|(px)[1]<< 8|(px)[0]

static inline
void U16_TO_BE(unsigned char *px, uint16_t num)
{
    px[0] = (unsigned char)((num >>  8) & 0xFF);
    px[1] = (unsigned char)((num >>  0) & 0xFF);
}

static inline
void U32_TO_BE(unsigned char *px, uint32_t num)
{
    px[0] = (unsigned char)((num >> 24) & 0xFF);
    px[1] = (unsigned char)((num >> 16) & 0xFF);
    px[2] = (unsigned char)((num >>  8) & 0xFF);
    px[3] = (unsigned char)((num >>  0) & 0xFF);
}

static inline
void U64_TO_BE(unsigned char *px, uint64_t num)
{
    px[0] = (unsigned char)((num >> 56) & 0xFF);
    px[1] = (unsigned char)((num >> 48) & 0xFF);
    px[2] = (unsigned char)((num >> 40) & 0xFF);
    px[3] = (unsigned char)((num >> 32) & 0xFF);
    px[4] = (unsigned char)((num >> 24) & 0xFF);
    px[5] = (unsigned char)((num >> 16) & 0xFF);
    px[6] = (unsigned char)((num >>  8) & 0xFF);
    px[7] = (unsigned char)((num >>  0) & 0xFF);
}

static inline
void U16_TO_LE(unsigned char *px, uint16_t num)
{
    px[1] = (unsigned char)((num >>  8) & 0xFF);
    px[0] = (unsigned char)((num >>  0) & 0xFF);
}

static inline
void U32_TO_LE(unsigned char *px, uint32_t num)
{
    px[3] = (unsigned char)((num >> 24) & 0xFF);
    px[2] = (unsigned char)((num >> 16) & 0xFF);
    px[1] = (unsigned char)((num >>  8) & 0xFF);
    px[0] = (unsigned char)((num >>  0) & 0xFF);
}

static inline
void U64_TO_LE(unsigned char *px, uint64_t num)
{
    px[7] = (unsigned char)((num >> 56) & 0xFF);
    px[6] = (unsigned char)((num >> 48) & 0xFF);
    px[5] = (unsigned char)((num >> 40) & 0xFF);
    px[4] = (unsigned char)((num >> 32) & 0xFF);
    px[3] = (unsigned char)((num >> 24) & 0xFF);
    px[2] = (unsigned char)((num >> 16) & 0xFF);
    px[1] = (unsigned char)((num >>  8) & 0xFF);
    px[0] = (unsigned char)((num >>  0) & 0xFF);
}

#endif
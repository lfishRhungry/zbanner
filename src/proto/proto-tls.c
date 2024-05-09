#ifndef NOT_FOUND_OPENSSL

#include <string.h>

#include "proto-tls.h"
#include "../util-data/data-convert.h"

static const char *TlsGreaseList[] = {
   "\x0a\x0a", "\x1a\x1a", "\x2a\x2a", "\x3a\x3a",
   "\x4a\x4a", "\x5a\x5a", "\x6a\x6a", "\x7a\x7a",
   "\x8a\x8a", "\x9a\x9a", "\xaa\xaa", "\xba\xba",
   "\xca\xca", "\xda\xda", "\xea\xea", "\xfa\xfa",
};

uint16_t tls_get_a_grease(unsigned seed)
{
    unsigned idx    = seed%(ARRAY_SIZE(TlsGreaseList));
    uint16_t grease = BE_TO_U16(TlsGreaseList[idx]);
    return grease;
}

size_t tls_load_ext_sni(unsigned char *px, const char *name)
{
    size_t name_len = strlen(name);
    if (name_len==0) return 0;

    size_t r_len = 0;

    /*Extension Type: Server Name*/
    px[0]  = 0x00;
    px[1]  = 0x00;

    U16_TO_BE(px, TLSEXT_TYPE_server_name);
    px    += 2;
    r_len += 2;

    /*Extension Length*/
    U16_TO_BE(px, name_len+5);
    px    += 2;
    r_len += 2;

    /*ServerName List Length*/
    U16_TO_BE(px, name_len+3);
    px    += 2;
    r_len += 2;

    /*ServerName Type: host*/
    px[0]  = 0x00;
    px    += 1;
    r_len += 1;

    /*ServerName Length*/
    U16_TO_BE(px, name_len);
    px    += 2;
    r_len += 2;

    /*ServerName*/
    memcpy(px, name, name_len);
    r_len += name_len;

    return r_len;
}

size_t tls_load_ext_alpn_proto(unsigned char *px, const char *proto)
{
    px[0] = (unsigned char)strlen(proto);
    memcpy(px+1, proto, strlen(proto));
    return strlen(proto)+1;
}

size_t tls_load_ext_alpn(unsigned char *px, const char **proto_list, unsigned proto_count)
{
    if (proto_count==0) return 0;

    U16_TO_BE(px, TLSEXT_TYPE_application_layer_protocol_negotiation);

    unsigned char *proto_start = px + 6;
    size_t tmp_len;

    for (unsigned i=0; i<proto_count; i++) {
        tmp_len = tls_load_ext_alpn_proto(proto_start, proto_list[i]);
        proto_start += tmp_len;
    }

    uint16_t alpn_len = proto_start - (px+6);
    uint16_t ext_len  = alpn_len + 2;

    U16_TO_BE(px+2, ext_len);
    U16_TO_BE(px+4, alpn_len);

    return ((size_t)ext_len) + 4;
}

#endif /*ifndef NOT_FOUND_OPENSSL*/
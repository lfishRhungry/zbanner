#include <string.h>

#include "proto-tls.h"

static const char *TlsGreaseList[] = {
   "\x0a\x0a", "\x1a\x1a", "\x2a\x2a", "\x3a\x3a",
   "\x4a\x4a", "\x5a\x5a", "\x6a\x6a", "\x7a\x7a",
   "\x8a\x8a", "\x9a\x9a", "\xaa\xaa", "\xba\xba",
   "\xca\xca", "\xda\xda", "\xea\xea", "\xfa\xfa",
};

uint16_t tls_get_a_grease(unsigned seed)
{
    unsigned idx    = seed%(sizeof(TlsGreaseList)/sizeof(const char *));
    uint16_t grease = TlsGreaseList[idx][0] << 8 | TlsGreaseList[idx][1];
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

    memcpy(px, TLS_EXT_TYPE_SERVER_NAME, sizeof(TLS_EXT_TYPE_SERVER_NAME)-1);
    px    += (sizeof(TLS_EXT_TYPE_SERVER_NAME)-1);
    r_len += (sizeof(TLS_EXT_TYPE_SERVER_NAME)-1);

    /*Extension Length*/
    px[0]  = ((name_len+5) >> 8) & 0xFF;
    px[1]  = ((name_len+5) >> 0) & 0xFF;
    px    += 2;
    r_len += 2;

    /*ServerName List Length*/
    px[0]  = ((name_len+3) >> 8) & 0xFF;
    px[1]  = ((name_len+3) >> 0) & 0xFF;
    px    += 2;
    r_len += 2;

    /*ServerName Type: host*/
    px[0]  = 0x00;
    px    += 1;
    r_len += 1;

    /*ServerName Length*/
    px[0]  = ((name_len) >> 8) & 0xFF;
    px[1]  = ((name_len) >> 0) & 0xFF;
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

    memcpy(px, TLS_EXT_APP_LAYER_PROTO_NEGOTIATION, sizeof(TLS_EXT_APP_LAYER_PROTO_NEGOTIATION)-1);

    unsigned char *proto_start = px + 6;
    size_t tmp_len;

    for (unsigned i=0; i<proto_count; i++) {
        tmp_len = tls_load_ext_alpn_proto(proto_start, proto_list[i]);
        proto_start += tmp_len;
    }

    uint16_t alpn_len = proto_start - (px+6);
    uint16_t ext_len  = alpn_len + 2;

    px[2] = (ext_len  >> 8) & 0xFF;
    px[3] = (ext_len  >> 0) & 0xFF;
    px[4] = (alpn_len >> 8) & 0xFF;
    px[5] = (alpn_len >> 0) & 0xFF;

    return ((size_t)ext_len) + 4;
}
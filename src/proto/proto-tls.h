/*
 * I cannot find a light, proper and convenient TLS library
 * for purpose of probing. So I try to implement the part of
 * ClientHello and ServerHello.
*/

/*
   TLS1.2 RFC5246

Message flow for a full handshake

      Client                                               Server

      ClientHello                  -------->
                                                      ServerHello
                                                     Certificate*
                                               ServerKeyExchange*
                                              CertificateRequest*
                                   <--------      ServerHelloDone
      Certificate*
      ClientKeyExchange
      CertificateVerify*
      [ChangeCipherSpec]
      Finished                     -------->
                                               [ChangeCipherSpec]
                                   <--------             Finished
      Application Data             <------->     Application Data

Message flow for an abbreviated handshake

      Client                                                Server

      ClientHello                   -------->
                                                       ServerHello
                                                [ChangeCipherSpec]
                                    <--------             Finished
      [ChangeCipherSpec]
      Finished                      -------->
      Application Data              <------->     Application Data
*/


/*
   TLS1.3 RFC8446

Message Flow for Full TLS Handshake

       Client                                           Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*       -------->
                                                  ServerHello  ^ Key
                                                 + key_share*  | Exch
                                            + pre_shared_key*  v
                                        {EncryptedExtensions}  ^  Server
                                        {CertificateRequest*}  v  Params
                                               {Certificate*}  ^
                                         {CertificateVerify*}  | Auth
                                                   {Finished}  v
                               <--------  [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}              -------->
       [Application Data]      <------->  [Application Data]

              +  Indicates noteworthy extensions sent in the
                 previously noted message.

              *  Indicates optional or situation-dependent
                 messages/extensions that are not always sent.

              {} Indicates messages protected using keys
                 derived from a [sender]_handshake_traffic_secret.

              [] Indicates messages protected using keys
                 derived from [sender]_application_traffic_secret_N.

Message Flow for a 0-RTT Handshake

 Client                                               Server

         ClientHello
         + early_data
         + key_share*
         + psk_key_exchange_modes
         + pre_shared_key
         (Application Data*)     -------->
                                                         ServerHello
                                                    + pre_shared_key
                                                        + key_share*
                                               {EncryptedExtensions}
                                                       + early_data*
                                                          {Finished}
                                 <--------       [Application Data*]
         (EndOfEarlyData)
         {Finished}              -------->
         [Application Data]      <------->        [Application Data]

               +  Indicates noteworthy extensions sent in the
                  previously noted message.

               *  Indicates optional or situation-dependent
                  messages/extensions that are not always sent.

               () Indicates messages protected using keys
                  derived from a client_early_traffic_secret.

               {} Indicates messages protected using keys
                  derived from a [sender]_handshake_traffic_secret.

               [] Indicates messages protected using keys
                  derived from [sender]_application_traffic_secret_N.
*/

#ifndef PROTO_TLS_H
#define PROTO_TLS_H

#include <stdlib.h>
#include <stdint.h>

#define TLS_CLIENTHELLO_MAX_LEN 1024

enum TLS_Version {
    SSLv3_0,
    TLSv1_0,
    TLSv1_1,
    TLSv1_2,
    TLSv1_3,
};

/*
 * Record Layer Content Type
*/
#define TLS_RECORD_CONTENT_TYPE_CHANGE_CIPHER_SPEC              '\x14'
#define TLS_RECORD_CONTENT_TYPE_ALERT                           '\x15'
#define TLS_RECORD_CONTENT_TYPE_HANDSHAKE                       '\x16'
#define TLS_RECORD_CONTENT_TYPE_APP_DATA                        '\x17'

/*
 * Handshake Type
*/
#define TLS_HANDSHAKE_TYPE_CLIENTHELLO                          '\x01'
#define TLS_HANDSHAKE_TYPE_SERVERHELLO                          '\x02'

/*
 * TLS Version
*/
#define TLS_VER_SSL_3_0                                         "\x03\x00"
#define TLS_VER_TLS_1_0                                         "\x03\x01"
#define TLS_VER_TLS_1_1                                         "\x03\x02"
#define TLS_VER_TLS_1_2                                         "\x03\x03"
#define TLS_VER_TLS_1_3                                         "\x03\x04"

/*
 * Cipher Suites
*/
      /*Description                                             Value             DTLS-OK    Recommended    Reference*/
#define TLS_NULL_WITH_NULL_NULL                                 "\x00\x00"    /*    Y             N         [RFC5246]    */
#define TLS_RSA_WITH_NULL_MD5                                   "\x00\x01"    /*    Y             N         [RFC5246]    */
#define TLS_RSA_WITH_NULL_SHA                                   "\x00\x02"    /*    Y             N         [RFC5246]    */
#define TLS_RSA_EXPORT_WITH_RC4_40_MD5                          "\x00\x03"    /*    N             N         [RFC4346][RFC6347]    */
#define TLS_RSA_WITH_RC4_128_MD5                                "\x00\x04"    /*    N             N         [RFC5246][RFC6347]    */
#define TLS_RSA_WITH_RC4_128_SHA                                "\x00\x05"    /*    N             N         [RFC5246][RFC6347]    */
#define TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5                      "\x00\x06"    /*    Y             N         [RFC4346]    */
#define TLS_RSA_WITH_IDEA_CBC_SHA                               "\x00\x07"    /*    Y             N         [RFC8996]    */
#define TLS_RSA_EXPORT_WITH_DES40_CBC_SHA                       "\x00\x08"    /*    Y             N         [RFC4346]    */
#define TLS_RSA_WITH_DES_CBC_SHA                                "\x00\x09"    /*    Y             N         [RFC8996]    */
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA                           "\x00\x0A"    /*    Y             N         [RFC5246]    */
#define TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA                    "\x00\x0B"    /*    Y             N         [RFC4346]    */
#define TLS_DH_DSS_WITH_DES_CBC_SHA                             "\x00\x0C"    /*    Y             N         [RFC8996]    */
#define TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA                        "\x00\x0D"    /*    Y             N         [RFC5246]    */
#define TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA                    "\x00\x0E"    /*    Y             N         [RFC4346]    */
#define TLS_DH_RSA_WITH_DES_CBC_SHA                             "\x00\x0F"    /*    Y             N         [RFC8996]    */
#define TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA                        "\x00\x10"    /*    Y             N         [RFC5246]    */
#define TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA                   "\x00\x11"    /*    Y             N         [RFC4346]    */
#define TLS_DHE_DSS_WITH_DES_CBC_SHA                            "\x00\x12"    /*    Y             N         [RFC8996]    */
#define TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA                       "\x00\x13"    /*    Y             N         [RFC5246]    */
#define TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA                   "\x00\x14"    /*    Y             N         [RFC4346]    */
#define TLS_DHE_RSA_WITH_DES_CBC_SHA                            "\x00\x15"    /*    Y             N         [RFC8996]    */
#define TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA                       "\x00\x16"    /*    Y             N         [RFC5246]    */
#define TLS_DH_anon_EXPORT_WITH_RC4_40_MD5                      "\x00\x17"    /*    N             N         [RFC4346][RFC6347]    */
#define TLS_DH_anon_WITH_RC4_128_MD5                            "\x00\x18"    /*    N             N         [RFC5246][RFC6347]    */
#define TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA                   "\x00\x19"    /*    Y             N         [RFC4346]    */
#define TLS_DH_anon_WITH_DES_CBC_SHA                            "\x00\x1A"    /*    Y             N         [RFC8996]    */
#define TLS_DH_anon_WITH_3DES_EDE_CBC_SHA                       "\x00\x1B"    /*    Y             N         [RFC5246]    */
#define TLS_KRB5_WITH_DES_CBC_SHA                               "\x00\x1E"    /*    Y             N         [RFC2712]    */
#define TLS_KRB5_WITH_3DES_EDE_CBC_SHA                          "\x00\x1F"    /*    Y             N         [RFC2712]    */
#define TLS_KRB5_WITH_RC4_128_SHA                               "\x00\x20"    /*    N             N         [RFC2712][RFC6347]    */
#define TLS_KRB5_WITH_IDEA_CBC_SHA                              "\x00\x21"    /*    Y             N         [RFC2712]    */
#define TLS_KRB5_WITH_DES_CBC_MD5                               "\x00\x22"    /*    Y             N         [RFC2712]    */
#define TLS_KRB5_WITH_3DES_EDE_CBC_MD5                          "\x00\x23"    /*    Y             N         [RFC2712]    */
#define TLS_KRB5_WITH_RC4_128_MD5                               "\x00\x24"    /*    N             N         [RFC2712][RFC6347]    */
#define TLS_KRB5_WITH_IDEA_CBC_MD5                              "\x00\x25"    /*    Y             N         [RFC2712]    */
#define TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA                     "\x00\x26"    /*    Y             N         [RFC2712]    */
#define TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA                     "\x00\x27"    /*    Y             N         [RFC2712]    */
#define TLS_KRB5_EXPORT_WITH_RC4_40_SHA                         "\x00\x28"    /*    N             N         [RFC2712][RFC6347]    */
#define TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5                     "\x00\x29"    /*    Y             N         [RFC2712]    */
#define TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5                     "\x00\x2A"    /*    Y             N         [RFC2712]    */
#define TLS_KRB5_EXPORT_WITH_RC4_40_MD5                         "\x00\x2B"    /*    N             N         [RFC2712][RFC6347]    */
#define TLS_PSK_WITH_NULL_SHA                                   "\x00\x2C"    /*    Y             N         [RFC4785]    */
#define TLS_DHE_PSK_WITH_NULL_SHA                               "\x00\x2D"    /*    Y             N         [RFC4785]    */
#define TLS_RSA_PSK_WITH_NULL_SHA                               "\x00\x2E"    /*    Y             N         [RFC4785]    */
#define TLS_RSA_WITH_AES_128_CBC_SHA                            "\x00\x2F"    /*    Y             N         [RFC5246]    */
#define TLS_DH_DSS_WITH_AES_128_CBC_SHA                         "\x00\x30"    /*    Y             N         [RFC5246]    */
#define TLS_DH_RSA_WITH_AES_128_CBC_SHA                         "\x00\x31"    /*    Y             N         [RFC5246]    */
#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA                        "\x00\x32"    /*    Y             N         [RFC5246]    */
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA                        "\x00\x33"    /*    Y             N         [RFC5246]    */
#define TLS_DH_anon_WITH_AES_128_CBC_SHA                        "\x00\x34"    /*    Y             N         [RFC5246]    */
#define TLS_RSA_WITH_AES_256_CBC_SHA                            "\x00\x35"    /*    Y             N         [RFC5246]    */
#define TLS_DH_DSS_WITH_AES_256_CBC_SHA                         "\x00\x36"    /*    Y             N         [RFC5246]    */
#define TLS_DH_RSA_WITH_AES_256_CBC_SHA                         "\x00\x37"    /*    Y             N         [RFC5246]    */
#define TLS_DHE_DSS_WITH_AES_256_CBC_SHA                        "\x00\x38"    /*    Y             N         [RFC5246]    */
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA                        "\x00\x39"    /*    Y             N         [RFC5246]    */
#define TLS_DH_anon_WITH_AES_256_CBC_SHA                        "\x00\x3A"    /*    Y             N         [RFC5246]    */
#define TLS_RSA_WITH_NULL_SHA256                                "\x00\x3B"    /*    Y             N         [RFC5246]    */
#define TLS_RSA_WITH_AES_128_CBC_SHA256                         "\x00\x3C"    /*    Y             N         [RFC5246]    */
#define TLS_RSA_WITH_AES_256_CBC_SHA256                         "\x00\x3D"    /*    Y             N         [RFC5246]    */
#define TLS_DH_DSS_WITH_AES_128_CBC_SHA256                      "\x00\x3E"    /*    Y             N         [RFC5246]    */
#define TLS_DH_RSA_WITH_AES_128_CBC_SHA256                      "\x00\x3F"    /*    Y             N         [RFC5246]    */
#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA256                     "\x00\x40"    /*    Y             N         [RFC5246]    */
#define TLS_RSA_WITH_CAMELLIA_128_CBC_SHA                       "\x00\x41"    /*    Y             N         [RFC5932]    */
#define TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA                    "\x00\x42"    /*    Y             N         [RFC5932]    */
#define TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA                    "\x00\x43"    /*    Y             N         [RFC5932]    */
#define TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA                   "\x00\x44"    /*    Y             N         [RFC5932]    */
#define TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA                   "\x00\x45"    /*    Y             N         [RFC5932]    */
#define TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA                   "\x00\x46"    /*    Y             N         [RFC5932]    */
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256                     "\x00\x67"    /*    Y             N         [RFC5246]    */
#define TLS_DH_DSS_WITH_AES_256_CBC_SHA256                      "\x00\x68"    /*    Y             N         [RFC5246]    */
#define TLS_DH_RSA_WITH_AES_256_CBC_SHA256                      "\x00\x69"    /*    Y             N         [RFC5246]    */
#define TLS_DHE_DSS_WITH_AES_256_CBC_SHA256                     "\x00\x6A"    /*    Y             N         [RFC5246]    */
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256                     "\x00\x6B"    /*    Y             N         [RFC5246]    */
#define TLS_DH_anon_WITH_AES_128_CBC_SHA256                     "\x00\x6C"    /*    Y             N         [RFC5246]    */
#define TLS_DH_anon_WITH_AES_256_CBC_SHA256                     "\x00\x6D"    /*    Y             N         [RFC5246]    */
#define TLS_RSA_WITH_CAMELLIA_256_CBC_SHA                       "\x00\x84"    /*    Y             N         [RFC5932]    */
#define TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA                    "\x00\x85"    /*    Y             N         [RFC5932]    */
#define TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA                    "\x00\x86"    /*    Y             N         [RFC5932]    */
#define TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA                   "\x00\x87"    /*    Y             N         [RFC5932]    */
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA                   "\x00\x88"    /*    Y             N         [RFC5932]    */
#define TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA                   "\x00\x89"    /*    Y             N         [RFC5932]    */
#define TLS_PSK_WITH_RC4_128_SHA                                "\x00\x8A"    /*    N             N         [RFC4279][RFC6347]    */
#define TLS_PSK_WITH_3DES_EDE_CBC_SHA                           "\x00\x8B"    /*    Y             N         [RFC4279]    */
#define TLS_PSK_WITH_AES_128_CBC_SHA                            "\x00\x8C"    /*    Y             N         [RFC4279]    */
#define TLS_PSK_WITH_AES_256_CBC_SHA                            "\x00\x8D"    /*    Y             N         [RFC4279]    */
#define TLS_DHE_PSK_WITH_RC4_128_SHA                            "\x00\x8E"    /*    N             N         [RFC4279][RFC6347]    */
#define TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA                       "\x00\x8F"    /*    Y             N         [RFC4279]    */
#define TLS_DHE_PSK_WITH_AES_128_CBC_SHA                        "\x00\x90"    /*    Y             N         [RFC4279]    */
#define TLS_DHE_PSK_WITH_AES_256_CBC_SHA                        "\x00\x91"    /*    Y             N         [RFC4279]    */
#define TLS_RSA_PSK_WITH_RC4_128_SHA                            "\x00\x92"    /*    N             N         [RFC4279][RFC6347]    */
#define TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA                       "\x00\x93"    /*    Y             N         [RFC4279]    */
#define TLS_RSA_PSK_WITH_AES_128_CBC_SHA                        "\x00\x94"    /*    Y             N         [RFC4279]    */
#define TLS_RSA_PSK_WITH_AES_256_CBC_SHA                        "\x00\x95"    /*    Y             N         [RFC4279]    */
#define TLS_RSA_WITH_SEED_CBC_SHA                               "\x00\x96"    /*    Y             N         [RFC4162]    */
#define TLS_DH_DSS_WITH_SEED_CBC_SHA                            "\x00\x97"    /*    Y             N         [RFC4162]    */
#define TLS_DH_RSA_WITH_SEED_CBC_SHA                            "\x00\x98"    /*    Y             N         [RFC4162]    */
#define TLS_DHE_DSS_WITH_SEED_CBC_SHA                           "\x00\x99"    /*    Y             N         [RFC4162]    */
#define TLS_DHE_RSA_WITH_SEED_CBC_SHA                           "\x00\x9A"    /*    Y             N         [RFC4162]    */
#define TLS_DH_anon_WITH_SEED_CBC_SHA                           "\x00\x9B"    /*    Y             N         [RFC4162]    */
#define TLS_RSA_WITH_AES_128_GCM_SHA256                         "\x00\x9C"    /*    Y             N         [RFC5288]    */
#define TLS_RSA_WITH_AES_256_GCM_SHA384                         "\x00\x9D"    /*    Y             N         [RFC5288]    */
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256                     "\x00\x9E"    /*    Y             Y         [RFC5288]    */
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384                     "\x00\x9F"    /*    Y             Y         [RFC5288]    */
#define TLS_DH_RSA_WITH_AES_128_GCM_SHA256                      "\x00\xA0"    /*    Y             N         [RFC5288]    */
#define TLS_DH_RSA_WITH_AES_256_GCM_SHA384                      "\x00\xA1"    /*    Y             N         [RFC5288]    */
#define TLS_DHE_DSS_WITH_AES_128_GCM_SHA256                     "\x00\xA2"    /*    Y             N         [RFC5288]    */
#define TLS_DHE_DSS_WITH_AES_256_GCM_SHA384                     "\x00\xA3"    /*    Y             N         [RFC5288]    */
#define TLS_DH_DSS_WITH_AES_128_GCM_SHA256                      "\x00\xA4"    /*    Y             N         [RFC5288]    */
#define TLS_DH_DSS_WITH_AES_256_GCM_SHA384                      "\x00\xA5"    /*    Y             N         [RFC5288]    */
#define TLS_DH_anon_WITH_AES_128_GCM_SHA256                     "\x00\xA6"    /*    Y             N         [RFC5288]    */
#define TLS_DH_anon_WITH_AES_256_GCM_SHA384                     "\x00\xA7"    /*    Y             N         [RFC5288]    */
#define TLS_PSK_WITH_AES_128_GCM_SHA256                         "\x00\xA8"    /*    Y             N         [RFC5487]    */
#define TLS_PSK_WITH_AES_256_GCM_SHA384                         "\x00\xA9"    /*    Y             N         [RFC5487]    */
#define TLS_DHE_PSK_WITH_AES_128_GCM_SHA256                     "\x00\xAA"    /*    Y             Y         [RFC5487]    */
#define TLS_DHE_PSK_WITH_AES_256_GCM_SHA384                     "\x00\xAB"    /*    Y             Y         [RFC5487]    */
#define TLS_RSA_PSK_WITH_AES_128_GCM_SHA256                     "\x00\xAC"    /*    Y             N         [RFC5487]    */
#define TLS_RSA_PSK_WITH_AES_256_GCM_SHA384                     "\x00\xAD"    /*    Y             N         [RFC5487]    */
#define TLS_PSK_WITH_AES_128_CBC_SHA256                         "\x00\xAE"    /*    Y             N         [RFC5487]    */
#define TLS_PSK_WITH_AES_256_CBC_SHA384                         "\x00\xAF"    /*    Y             N         [RFC5487]    */
#define TLS_PSK_WITH_NULL_SHA256                                "\x00\xB0"    /*    Y             N         [RFC5487]    */
#define TLS_PSK_WITH_NULL_SHA384                                "\x00\xB1"    /*    Y             N         [RFC5487]    */
#define TLS_DHE_PSK_WITH_AES_128_CBC_SHA256                     "\x00\xB2"    /*    Y             N         [RFC5487]    */
#define TLS_DHE_PSK_WITH_AES_256_CBC_SHA384                     "\x00\xB3"    /*    Y             N         [RFC5487]    */
#define TLS_DHE_PSK_WITH_NULL_SHA256                            "\x00\xB4"    /*    Y             N         [RFC5487]    */
#define TLS_DHE_PSK_WITH_NULL_SHA384                            "\x00\xB5"    /*    Y             N         [RFC5487]    */
#define TLS_RSA_PSK_WITH_AES_128_CBC_SHA256                     "\x00\xB6"    /*    Y             N         [RFC5487]    */
#define TLS_RSA_PSK_WITH_AES_256_CBC_SHA384                     "\x00\xB7"    /*    Y             N         [RFC5487]    */
#define TLS_RSA_PSK_WITH_NULL_SHA256                            "\x00\xB8"    /*    Y             N         [RFC5487]    */
#define TLS_RSA_PSK_WITH_NULL_SHA384                            "\x00\xB9"    /*    Y             N         [RFC5487]    */
#define TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256                    "\x00\xBA"    /*    Y             N         [RFC5932]    */
#define TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256                 "\x00\xBB"    /*    Y             N         [RFC5932]    */
#define TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256                 "\x00\xBC"    /*    Y             N         [RFC5932]    */
#define TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256                "\x00\xBD"    /*    Y             N         [RFC5932]    */
#define TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256                "\x00\xBE"    /*    Y             N         [RFC5932]    */
#define TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256                "\x00\xBF"    /*    Y             N         [RFC5932]    */
#define TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256                    "\x00\xC0"    /*    Y             N         [RFC5932]    */
#define TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256                 "\x00\xC1"    /*    Y             N         [RFC5932]    */
#define TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256                 "\x00\xC2"    /*    Y             N         [RFC5932]    */
#define TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256                "\x00\xC3"    /*    Y             N         [RFC5932]    */
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256                "\x00\xC4"    /*    Y             N         [RFC5932]    */
#define TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256                "\x00\xC5"    /*    Y             N         [RFC5932]    */
#define TLS_SM4_GCM_SM3                                         "\x00\xC6"    /*    N             N         [RFC8998]    */
#define TLS_SM4_CCM_SM3                                         "\x00\xC7"    /*    N             N         [RFC8998]    */
#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV                       "\x00\xFF"    /*    Y             N         [RFC5746]    */
#define TLS_AES_128_GCM_SHA256                                  "\x13\x01"    /*    Y             Y         [RFC8446]    */
#define TLS_AES_256_GCM_SHA384                                  "\x13\x02"    /*    Y             Y         [RFC8446]    */
#define TLS_CHACHA20_POLY1305_SHA256                            "\x13\x03"    /*    Y             Y         [RFC8446]    */
#define TLS_AES_128_CCM_SHA256                                  "\x13\x04"    /*    Y             Y         [RFC8446]    */
#define TLS_AES_128_CCM_8_SHA256                                "\x13\x05"    /*    Y             N         [RFC8446][IESG Action 2018-08-16]    */
#define TLS_AEGIS_256_SHA512                                    "\x13\x06"    /*    Y             N         [draft-irtf-cfrg-aegis-aead-08]    */
#define TLS_AEGIS_128L_SHA256                                   "\x13\x07"    /*    Y             N         [draft-irtf-cfrg-aegis-aead-08]    */
#define TLS_FALLBACK_SCSV                                       "\x56\x00"    /*    Y             N         [RFC7507]    */
#define TLS_ECDH_ECDSA_WITH_NULL_SHA                            "\xC0\x01"    /*    Y             N         [RFC8422]    */
#define TLS_ECDH_ECDSA_WITH_RC4_128_SHA                         "\xC0\x02"    /*    N             N         [RFC8422][RFC6347]    */
#define TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA                    "\xC0\x03"    /*    Y             N         [RFC8422]    */
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA                     "\xC0\x04"    /*    Y             N         [RFC8422]    */
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA                     "\xC0\x05"    /*    Y             N         [RFC8422]    */
#define TLS_ECDHE_ECDSA_WITH_NULL_SHA                           "\xC0\x06"    /*    Y             N         [RFC8422]    */
#define TLS_ECDHE_ECDSA_WITH_RC4_128_SHA                        "\xC0\x07"    /*    N             N         [RFC8422][RFC6347]    */
#define TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA                   "\xC0\x08"    /*    Y             N         [RFC8422]    */
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA                    "\xC0\x09"    /*    Y             N         [RFC8422]    */
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA                    "\xC0\x0A"    /*    Y             N         [RFC8422]    */
#define TLS_ECDH_RSA_WITH_NULL_SHA                              "\xC0\x0B"    /*    Y             N         [RFC8422]    */
#define TLS_ECDH_RSA_WITH_RC4_128_SHA                           "\xC0\x0C"    /*    N             N         [RFC8422][RFC6347]    */
#define TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA                      "\xC0\x0D"    /*    Y             N         [RFC8422]    */
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA                       "\xC0\x0E"    /*    Y             N         [RFC8422]    */
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA                       "\xC0\x0F"    /*    Y             N         [RFC8422]    */
#define TLS_ECDHE_RSA_WITH_NULL_SHA                             "\xC0\x10"    /*    Y             N         [RFC8422]    */
#define TLS_ECDHE_RSA_WITH_RC4_128_SHA                          "\xC0\x11"    /*    N             N         [RFC8422][RFC6347]    */
#define TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA                     "\xC0\x12"    /*    Y             N         [RFC8422]    */
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                      "\xC0\x13"    /*    Y             N         [RFC8422]    */
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                      "\xC0\x14"    /*    Y             N         [RFC8422]    */
#define TLS_ECDH_anon_WITH_NULL_SHA                             "\xC0\x15"    /*    Y             N         [RFC8422]    */
#define TLS_ECDH_anon_WITH_RC4_128_SHA                          "\xC0\x16"    /*    N             N         [RFC8422][RFC6347]    */
#define TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA                     "\xC0\x17"    /*    Y             N         [RFC8422]    */
#define TLS_ECDH_anon_WITH_AES_128_CBC_SHA                      "\xC0\x18"    /*    Y             N         [RFC8422]    */
#define TLS_ECDH_anon_WITH_AES_256_CBC_SHA                      "\xC0\x19"    /*    Y             N         [RFC8422]    */
#define TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA                       "\xC0\x1A"    /*    Y             N         [RFC5054]    */
#define TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA                   "\xC0\x1B"    /*    Y             N         [RFC5054]    */
#define TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA                   "\xC0\x1C"    /*    Y             N         [RFC5054]    */
#define TLS_SRP_SHA_WITH_AES_128_CBC_SHA                        "\xC0\x1D"    /*    Y             N         [RFC5054]    */
#define TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA                    "\xC0\x1E"    /*    Y             N         [RFC5054]    */
#define TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA                    "\xC0\x1F"    /*    Y             N         [RFC5054]    */
#define TLS_SRP_SHA_WITH_AES_256_CBC_SHA                        "\xC0\x20"    /*    Y             N         [RFC5054]    */
#define TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA                    "\xC0\x21"    /*    Y             N         [RFC5054]    */
#define TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA                    "\xC0\x22"    /*    Y             N         [RFC5054]    */
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256                 "\xC0\x23"    /*    Y             N         [RFC5289]    */
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384                 "\xC0\x24"    /*    Y             N         [RFC5289]    */
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256                  "\xC0\x25"    /*    Y             N         [RFC5289]    */
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384                  "\xC0\x26"    /*    Y             N         [RFC5289]    */
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256                   "\xC0\x27"    /*    Y             N         [RFC5289]    */
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384                   "\xC0\x28"    /*    Y             N         [RFC5289]    */
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256                    "\xC0\x29"    /*    Y             N         [RFC5289]    */
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384                    "\xC0\x2A"    /*    Y             N         [RFC5289]    */
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256                 "\xC0\x2B"    /*    Y             Y         [RFC5289]    */
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384                 "\xC0\x2C"    /*    Y             Y         [RFC5289]    */
#define TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256                  "\xC0\x2D"    /*    Y             N         [RFC5289]    */
#define TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384                  "\xC0\x2E"    /*    Y             N         [RFC5289]    */
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256                   "\xC0\x2F"    /*    Y             Y         [RFC5289]    */
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384                   "\xC0\x30"    /*    Y             Y         [RFC5289]    */
#define TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256                    "\xC0\x31"    /*    Y             N         [RFC5289]    */
#define TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384                    "\xC0\x32"    /*    Y             N         [RFC5289]    */
#define TLS_ECDHE_PSK_WITH_RC4_128_SHA                          "\xC0\x33"    /*    N             N         [RFC5489][RFC6347]    */
#define TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA                     "\xC0\x34"    /*    Y             N         [RFC5489]    */
#define TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA                      "\xC0\x35"    /*    Y             N         [RFC5489]    */
#define TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA                      "\xC0\x36"    /*    Y             N         [RFC5489]    */
#define TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256                   "\xC0\x37"    /*    Y             N         [RFC5489]    */
#define TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384                   "\xC0\x38"    /*    Y             N         [RFC5489]    */
#define TLS_ECDHE_PSK_WITH_NULL_SHA                             "\xC0\x39"    /*    Y             N         [RFC5489]    */
#define TLS_ECDHE_PSK_WITH_NULL_SHA256                          "\xC0\x3A"    /*    Y             N         [RFC5489]    */
#define TLS_ECDHE_PSK_WITH_NULL_SHA384                          "\xC0\x3B"    /*    Y             N         [RFC5489]    */
#define TLS_RSA_WITH_ARIA_128_CBC_SHA256                        "\xC0\x3C"    /*    Y             N         [RFC6209]    */
#define TLS_RSA_WITH_ARIA_256_CBC_SHA384                        "\xC0\x3D"    /*    Y             N         [RFC6209]    */
#define TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256                     "\xC0\x3E"    /*    Y             N         [RFC6209]    */
#define TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384                     "\xC0\x3F"    /*    Y             N         [RFC6209]    */
#define TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256                     "\xC0\x40"    /*    Y             N         [RFC6209]    */
#define TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384                     "\xC0\x41"    /*    Y             N         [RFC6209]    */
#define TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256                    "\xC0\x42"    /*    Y             N         [RFC6209]    */
#define TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384                    "\xC0\x43"    /*    Y             N         [RFC6209]    */
#define TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256                    "\xC0\x44"    /*    Y             N         [RFC6209]    */
#define TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384                    "\xC0\x45"    /*    Y             N         [RFC6209]    */
#define TLS_DH_anon_WITH_ARIA_128_CBC_SHA256                    "\xC0\x46"    /*    Y             N         [RFC6209]    */
#define TLS_DH_anon_WITH_ARIA_256_CBC_SHA384                    "\xC0\x47"    /*    Y             N         [RFC6209]    */
#define TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256                "\xC0\x48"    /*    Y             N         [RFC6209]    */
#define TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384                "\xC0\x49"    /*    Y             N         [RFC6209]    */
#define TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256                 "\xC0\x4A"    /*    Y             N         [RFC6209]    */
#define TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384                 "\xC0\x4B"    /*    Y             N         [RFC6209]    */
#define TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256                  "\xC0\x4C"    /*    Y             N         [RFC6209]    */
#define TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384                  "\xC0\x4D"    /*    Y             N         [RFC6209]    */
#define TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256                   "\xC0\x4E"    /*    Y             N         [RFC6209]    */
#define TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384                   "\xC0\x4F"    /*    Y             N         [RFC6209]    */
#define TLS_RSA_WITH_ARIA_128_GCM_SHA256                        "\xC0\x50"    /*    Y             N         [RFC6209]    */
#define TLS_RSA_WITH_ARIA_256_GCM_SHA384                        "\xC0\x51"    /*    Y             N         [RFC6209]    */
#define TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256                    "\xC0\x52"    /*    Y             N         [RFC6209]    */
#define TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384                    "\xC0\x53"    /*    Y             N         [RFC6209]    */
#define TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256                     "\xC0\x54"    /*    Y             N         [RFC6209]    */
#define TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384                     "\xC0\x55"    /*    Y             N         [RFC6209]    */
#define TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256                    "\xC0\x56"    /*    Y             N         [RFC6209]    */
#define TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384                    "\xC0\x57"    /*    Y             N         [RFC6209]    */
#define TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256                     "\xC0\x58"    /*    Y             N         [RFC6209]    */
#define TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384                     "\xC0\x59"    /*    Y             N         [RFC6209]    */
#define TLS_DH_anon_WITH_ARIA_128_GCM_SHA256                    "\xC0\x5A"    /*    Y             N         [RFC6209]    */
#define TLS_DH_anon_WITH_ARIA_256_GCM_SHA384                    "\xC0\x5B"    /*    Y             N         [RFC6209]    */
#define TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256                "\xC0\x5C"    /*    Y             N         [RFC6209]    */
#define TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384                "\xC0\x5D"    /*    Y             N         [RFC6209]    */
#define TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256                 "\xC0\x5E"    /*    Y             N         [RFC6209]    */
#define TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384                 "\xC0\x5F"    /*    Y             N         [RFC6209]    */
#define TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256                  "\xC0\x60"    /*    Y             N         [RFC6209]    */
#define TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384                  "\xC0\x61"    /*    Y             N         [RFC6209]    */
#define TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256                   "\xC0\x62"    /*    Y             N         [RFC6209]    */
#define TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384                   "\xC0\x63"    /*    Y             N         [RFC6209]    */
#define TLS_PSK_WITH_ARIA_128_CBC_SHA256                        "\xC0\x64"    /*    Y             N         [RFC6209]    */
#define TLS_PSK_WITH_ARIA_256_CBC_SHA384                        "\xC0\x65"    /*    Y             N         [RFC6209]    */
#define TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256                    "\xC0\x66"    /*    Y             N         [RFC6209]    */
#define TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384                    "\xC0\x67"    /*    Y             N         [RFC6209]    */
#define TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256                    "\xC0\x68"    /*    Y             N         [RFC6209]    */
#define TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384                    "\xC0\x69"    /*    Y             N         [RFC6209]    */
#define TLS_PSK_WITH_ARIA_128_GCM_SHA256                        "\xC0\x6A"    /*    Y             N         [RFC6209]    */
#define TLS_PSK_WITH_ARIA_256_GCM_SHA384                        "\xC0\x6B"    /*    Y             N         [RFC6209]    */
#define TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256                    "\xC0\x6C"    /*    Y             N         [RFC6209]    */
#define TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384                    "\xC0\x6D"    /*    Y             N         [RFC6209]    */
#define TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256                    "\xC0\x6E"    /*    Y             N         [RFC6209]    */
#define TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384                    "\xC0\x6F"    /*    Y             N         [RFC6209]    */
#define TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256                  "\xC0\x70"    /*    Y             N         [RFC6209]    */
#define TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384                  "\xC0\x71"    /*    Y             N         [RFC6209]    */
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256            "\xC0\x72"    /*    Y             N         [RFC6367]    */
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384            "\xC0\x73"    /*    Y             N         [RFC6367]    */
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256             "\xC0\x74"    /*    Y             N         [RFC6367]    */
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384             "\xC0\x75"    /*    Y             N         [RFC6367]    */
#define TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256              "\xC0\x76"    /*    Y             N         [RFC6367]    */
#define TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384              "\xC0\x77"    /*    Y             N         [RFC6367]    */
#define TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256               "\xC0\x78"    /*    Y             N         [RFC6367]    */
#define TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384               "\xC0\x79"    /*    Y             N         [RFC6367]    */
#define TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256                    "\xC0\x7A"    /*    Y             N         [RFC6367]    */
#define TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384                    "\xC0\x7B"    /*    Y             N         [RFC6367]    */
#define TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256                "\xC0\x7C"    /*    Y             N         [RFC6367]    */
#define TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384                "\xC0\x7D"    /*    Y             N         [RFC6367]    */
#define TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256                 "\xC0\x7E"    /*    Y             N         [RFC6367]    */
#define TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384                 "\xC0\x7F"    /*    Y             N         [RFC6367]    */
#define TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256                "\xC0\x80"    /*    Y             N         [RFC6367]    */
#define TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384                "\xC0\x81"    /*    Y             N         [RFC6367]    */
#define TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256                 "\xC0\x82"    /*    Y             N         [RFC6367]    */
#define TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384                 "\xC0\x83"    /*    Y             N         [RFC6367]    */
#define TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256                "\xC0\x84"    /*    Y             N         [RFC6367]    */
#define TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384                "\xC0\x85"    /*    Y             N         [RFC6367]    */
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256            "\xC0\x86"    /*    Y             N         [RFC6367]    */
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384            "\xC0\x87"    /*    Y             N         [RFC6367]    */
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256             "\xC0\x88"    /*    Y             N         [RFC6367]    */
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384             "\xC0\x89"    /*    Y             N         [RFC6367]    */
#define TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256              "\xC0\x8A"    /*    Y             N         [RFC6367]    */
#define TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384              "\xC0\x8B"    /*    Y             N         [RFC6367]    */
#define TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256               "\xC0\x8C"    /*    Y             N         [RFC6367]    */
#define TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384               "\xC0\x8D"    /*    Y             N         [RFC6367]    */
#define TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256                    "\xC0\x8E"    /*    Y             N         [RFC6367]    */
#define TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384                    "\xC0\x8F"    /*    Y             N         [RFC6367]    */
#define TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256                "\xC0\x90"    /*    Y             N         [RFC6367]    */
#define TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384                "\xC0\x91"    /*    Y             N         [RFC6367]    */
#define TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256                "\xC0\x92"    /*    Y             N         [RFC6367]    */
#define TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384                "\xC0\x93"    /*    Y             N         [RFC6367]    */
#define TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256                    "\xC0\x94"    /*    Y             N         [RFC6367]    */
#define TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384                    "\xC0\x95"    /*    Y             N         [RFC6367]    */
#define TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256                "\xC0\x96"    /*    Y             N         [RFC6367]    */
#define TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384                "\xC0\x97"    /*    Y             N         [RFC6367]    */
#define TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256                "\xC0\x98"    /*    Y             N         [RFC6367]    */
#define TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384                "\xC0\x99"    /*    Y             N         [RFC6367]    */
#define TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256              "\xC0\x9A"    /*    Y             N         [RFC6367]    */
#define TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384              "\xC0\x9B"    /*    Y             N         [RFC6367]    */
#define TLS_RSA_WITH_AES_128_CCM                                "\xC0\x9C"    /*    Y             N         [RFC6655]    */
#define TLS_RSA_WITH_AES_256_CCM                                "\xC0\x9D"    /*    Y             N         [RFC6655]    */
#define TLS_DHE_RSA_WITH_AES_128_CCM                            "\xC0\x9E"    /*    Y             Y         [RFC6655]    */
#define TLS_DHE_RSA_WITH_AES_256_CCM                            "\xC0\x9F"    /*    Y             Y         [RFC6655]    */
#define TLS_RSA_WITH_AES_128_CCM_8                              "\xC0\xA0"    /*    Y             N         [RFC6655]    */
#define TLS_RSA_WITH_AES_256_CCM_8                              "\xC0\xA1"    /*    Y             N         [RFC6655]    */
#define TLS_DHE_RSA_WITH_AES_128_CCM_8                          "\xC0\xA2"    /*    Y             N         [RFC6655]    */
#define TLS_DHE_RSA_WITH_AES_256_CCM_8                          "\xC0\xA3"    /*    N             N         [RFC6655]    */
#define TLS_PSK_WITH_AES_128_CCM                                "\xC0\xA4"    /*    Y             N         [RFC6655]    */
#define TLS_PSK_WITH_AES_256_CCM                                "\xC0\xA5"    /*    Y             N         [RFC6655]    */
#define TLS_DHE_PSK_WITH_AES_128_CCM                            "\xC0\xA6"    /*    Y             Y         [RFC6655]    */
#define TLS_DHE_PSK_WITH_AES_256_CCM                            "\xC0\xA7"    /*    Y             Y         [RFC6655]    */
#define TLS_PSK_WITH_AES_128_CCM_8                              "\xC0\xA8"    /*    Y             N         [RFC6655]    */
#define TLS_PSK_WITH_AES_256_CCM_8                              "\xC0\xA9"    /*    Y             N         [RFC6655]    */
#define TLS_PSK_DHE_WITH_AES_128_CCM_8                          "\xC0\xAA"    /*    Y             N         [RFC6655]    */
#define TLS_PSK_DHE_WITH_AES_256_CCM_8                          "\xC0\xAB"    /*    Y             N         [RFC6655]    */
#define TLS_ECDHE_ECDSA_WITH_AES_128_CCM                        "\xC0\xAC"    /*    Y             N         [RFC7251]    */
#define TLS_ECDHE_ECDSA_WITH_AES_256_CCM                        "\xC0\xAD"    /*    Y             N         [RFC7251]    */
#define TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8                      "\xC0\xAE"    /*    Y             N         [RFC7251]    */
#define TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8                      "\xC0\xAF"    /*    Y             N         [RFC7251]    */
#define TLS_ECCPWD_WITH_AES_128_GCM_SHA256                      "\xC0\xB0"    /*    Y             N         [RFC8492]    */
#define TLS_ECCPWD_WITH_AES_256_GCM_SHA384                      "\xC0\xB1"    /*    Y             N         [RFC8492]    */
#define TLS_ECCPWD_WITH_AES_128_CCM_SHA256                      "\xC0\xB2"    /*    Y             N         [RFC8492]    */
#define TLS_ECCPWD_WITH_AES_256_CCM_SHA384                      "\xC0\xB3"    /*    Y             N         [RFC8492]    */
#define TLS_SHA256_SHA256                                       "\xC0\xB4"    /*    Y             N         [RFC9150]    */
#define TLS_SHA384_SHA384                                       "\xC0\xB5"    /*    Y             N         [RFC9150]    */
#define TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC            "\xC1\x00"    /*    N             N         [RFC9189]    */
#define TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC                 "\xC1\x01"    /*    N             N         [RFC9189]    */
#define TLS_GOSTR341112_256_WITH_28147_CNT_IMIT                 "\xC1\x02"    /*    N             N         [RFC9189]    */
#define TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L               "\xC1\x03"    /*    N             N         [RFC9367]    */
#define TLS_GOSTR341112_256_WITH_MAGMA_MGM_L                    "\xC1\x04"    /*    N             N         [RFC9367]    */
#define TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S               "\xC1\x05"    /*    N             N         [RFC9367]    */
#define TLS_GOSTR341112_256_WITH_MAGMA_MGM_S                    "\xC1\x06"    /*    N             N         [RFC9367]    */
#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256             "\xCC\xA8"    /*    Y             Y         [RFC7905]    */
#define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256           "\xCC\xA9"    /*    Y             Y         [RFC7905]    */
#define TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256               "\xCC\xAA"    /*    Y             Y         [RFC7905]    */
#define TLS_PSK_WITH_CHACHA20_POLY1305_SHA256                   "\xCC\xAB"    /*    Y             N         [RFC7905]    */
#define TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256             "\xCC\xAC"    /*    Y             Y         [RFC7905]    */
#define TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256               "\xCC\xAD"    /*    Y             Y         [RFC7905]    */
#define TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256               "\xCC\xAE"    /*    Y             N         [RFC7905]    */
#define TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256                   "\xD0\x01"    /*    Y             Y         [RFC8442]    */
#define TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384                   "\xD0\x02"    /*    Y             Y         [RFC8442]    */
#define TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256                 "\xD0\x03"    /*    Y             N         [RFC8442]    */
#define TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256                   "\xD0\x05"    /*    Y             Y         [RFC8442]    */

/*
 * Extension Type
*/
#define TLS_EXT_TYPE_SERVER_NAME                                "\x00\x00"
#define TLS_EXT_EXTENDED_MASTER_SECRET                          "\x00\x17"
#define TLS_EXT_MAX_FRAGMENT_LENGTH                             "\x00\x01"
#define TLS_EXT_RENEGOTIATION_INFO                              "\xff\x01"
#define TLS_EXT_SUPPORTED_GROUPS                                "\x00\x0a"
#define TLS_EXT_EC_POINT_FORMATS                                "\x00\x0b"
#define TLS_EXT_SESSION_TICKET                                  "\x00\x23"
#define TLS_EXT_APP_LAYER_PROTO_NEGOTIATION                     "\x00\x10"
#define TLS_EXT_SIGNATURE_ALGORITHMS                            "\x00\x0d"
#define TLS_EXT_KEY_SHARE                                       "\x00\x33"
#define TLS_EXT_PSK_KEY_EXCHANGE_MODES                          "\x00\x2d"
#define TLS_EXT_SUPPORTED_VERSIONS                              "\x00\x2b"

/*
 * ALPN Proto Name
*/
#define TLS_EXT_ALPN_PROTO_HTTP_0_9                             "http/0.9"
#define TLS_EXT_ALPN_PROTO_HTTP_1_0                             "http/1.0"
#define TLS_EXT_ALPN_PROTO_HTTP_1_1                             "http/1.1"
#define TLS_EXT_ALPN_PROTO_SPDY_1                               "spdy/1"
#define TLS_EXT_ALPN_PROTO_SPDY_2                               "spdy/2"
#define TLS_EXT_ALPN_PROTO_SPDY_3                               "spdy/3"
#define TLS_EXT_ALPN_PROTO_HTTP_2_OVER_TLS                      "h2"
#define TLS_EXT_ALPN_PROTO_HTTP_2_OVER_CLEARTEXT                "h2c"
#define TLS_EXT_ALPN_PROTO_HTTP_QUIC                            "hq"      /*deprecated*/

/*
 * Key Share Group
*/
#define TLS_EXT_KEY_SHARE_GROUP_X25519                          "\x00\x1d"

/**
 * get a grease value by seed.
 * @param seed random seed provided by caller.
 * @return grease in uint16.
*/
uint16_t tls_get_a_grease(unsigned seed);

/**
 * load SNI extension to px
 * @param px buffer to load.
 * @param name servername in C string style.
 * @return length we have loaded.
*/
size_t tls_load_ext_sni(unsigned char *px, const char *name);

/**
 * load an alpn proto to px
 * @param px buffer to load.
 * @param proto an alpn proto in C string style.
 * @return length we have loaded.
*/
size_t tls_load_ext_alpn_proto(unsigned char *px, const char *proto);

/**
 * load alpn extension to px
 * @param px buffer to load.
 * @param proto_list alpn list in C style.
 * @param proto_count num of protos.
 * @return length we have loaded.
*/
size_t tls_load_ext_alpn(unsigned char *px, const char **proto_list, unsigned proto_count);

#endif
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

#ifndef NOT_FOUND_OPENSSL

#ifndef PROTO_TLS_H
#define PROTO_TLS_H

#include <stdlib.h>
#include <stdint.h>

#include <openssl/ssl.h>

#define TLS_CLIENTHELLO_MAX_LEN                    1024
/*
 * Record Layer Content Type
 */
#define TLS_RECORD_CONTENT_TYPE_CHANGE_CIPHER_SPEC '\x14'
#define TLS_RECORD_CONTENT_TYPE_ALERT              '\x15'
#define TLS_RECORD_CONTENT_TYPE_HANDSHAKE          '\x16'
#define TLS_RECORD_CONTENT_TYPE_APP_DATA           '\x17'
/*
 * Handshake Type
 */
#define TLS_HANDSHAKE_TYPE_CLIENTHELLO             '\x01'
#define TLS_HANDSHAKE_TYPE_SERVERHELLO             '\x02'
/*
 * ALPN Proto Name
 */
#define TLS_EXT_ALPN_PROTO_HTTP_0_9                "http/0.9"
#define TLS_EXT_ALPN_PROTO_HTTP_1_0                "http/1.0"
#define TLS_EXT_ALPN_PROTO_HTTP_1_1                "http/1.1"
#define TLS_EXT_ALPN_PROTO_SPDY_1                  "spdy/1"
#define TLS_EXT_ALPN_PROTO_SPDY_2                  "spdy/2"
#define TLS_EXT_ALPN_PROTO_SPDY_3                  "spdy/3"
#define TLS_EXT_ALPN_PROTO_HTTP_2_OVER_TLS         "h2"
#define TLS_EXT_ALPN_PROTO_HTTP_2_OVER_CLEARTEXT   "h2c"
#define TLS_EXT_ALPN_PROTO_HTTP_QUIC               "hq" /*deprecated*/
/*
 * Key Share Group
 */
#define TLS_EXT_KEY_SHARE_GROUP_X25519             "\x00\x1d"

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
size_t tls_load_ext_alpn(unsigned char *px, const char **proto_list,
                         unsigned proto_count);

#endif

#endif /*ifndef NOT_FOUND_OPENSSL*/
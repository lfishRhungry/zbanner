#ifndef NOT_FOUND_OPENSSL

#ifndef PROTO_JARM_H
#define PROTO_JARM_H

#include "proto-tls.h"

enum JarmCipherChoice {
    CipherList_ALL,
    CipherList_NO_1_3,
};

enum JarmCipherOrder {
    CipherOrder_FORWARD,
    CipherOrder_REVERSE,
    CipherOrder_TOP_HALF,    /*from middle to top*/
    CipherOrder_BOTTOM_HALF, /*from middle to bottom (without middle)*/
    CipherOrder_MIDDLE_OUT,  /*from middle to both edge (contains middle)*/
};

enum JarmGreaseUse {
    GreaseUse_YES,
    GreaseUse_NO,
};

enum JarmAlpnUse {
    AlpnUse_ALL,
    AlpnUse_RARE,
    AlpnUse_NULL,
};

enum JarmExtensionOrder {
    ExtOrder_FORWARD,
    ExtOrder_REVERSE,
};

enum JarmSupportVersionsExtension {
    SupportVerExt_1_2_SUPPORT, /*Only support up to TLSv1.2*/
    SupportVerExt_NO_SUPPORT,  /*No Supported Version Extension*/
    SupportVerExt_1_3_SUPPORT, /*Support up to TLSv1.3*/
};

struct JarmConfig {
    char                             *servername; /* end with zero */
    unsigned                          dst_port;
    uint16_t                          version;
    enum JarmCipherChoice             cipher_list;
    enum JarmCipherOrder              cipher_order;
    enum JarmGreaseUse                grease_use;
    enum JarmAlpnUse                  alpn_use;
    enum JarmSupportVersionsExtension support_ver_ext;
    enum JarmExtensionOrder           ext_order;
};

/**
 * Create a client with specified Jarm Config for jarm probing.
 * @param jc config of jarm.
 * @param buf buffer to load CH probe.
 * @param buf_len length of buffer.
 * @return length of CH probe or 0 if error happened.
 */
size_t jarm_create_ch(struct JarmConfig *jc, unsigned char *buf,
                      unsigned buf_len);

/**
 * Decpher ServerHello in JARM format to c string
 * We should insure the payload is a valid ServerHello.(include ALERT)
 */
size_t jarm_decipher_one(const unsigned char *payload, size_t payload_len,
                         char *res_buf, size_t res_max);

#endif

#endif /*ifndef NOT_FOUND_OPENSSL*/
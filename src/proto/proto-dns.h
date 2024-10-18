/**
 * This DNS resolver are born from
 * MASSDNS: https://github.com/blechschmidt/massdns
 *
 * I do some key changes to adapt to xtate.
 * e.g. make it be thread safe.
 * and fix some bugs e.g. memcpy/memmove
 *
 * Modified: sharkocha 2024
 */
// SPDX-License-Identifier: GPL-3.0-only

#ifndef PROTO_DNS_H
#define PROTO_DNS_H

#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdio.h>

#include "../target/target-ipaddress.h"
#include "../util-misc/cross.h"
#include "../pixie/pixie-sockets.h"

typedef enum {
    DNS_REC_INVALID    = -1, // Error code
    DNS_REC_A          = 1,
    DNS_REC_AAAA       = 28,
    DNS_REC_AFSDB      = 18,
    DNS_REC_ANY        = 255,
    DNS_REC_APL        = 42,
    DNS_REC_CAA        = 257,
    DNS_REC_CDNSKEY    = 60,
    DNS_REC_CDS        = 59,
    DNS_REC_CERT       = 37,
    DNS_REC_CNAME      = 5,
    DNS_REC_DHCID      = 49,
    DNS_REC_DLV        = 32769,
    DNS_REC_DNAME      = 39,
    DNS_REC_DNSKEY     = 48,
    DNS_REC_DS         = 43,
    DNS_REC_HIP        = 55,
    DNS_REC_IPSECKEY   = 45,
    DNS_REC_KEY        = 25,
    DNS_REC_KX         = 36,
    DNS_REC_LOC        = 29,
    DNS_REC_MX         = 15,
    DNS_REC_NAPTR      = 35,
    DNS_REC_NS         = 2,
    DNS_REC_NSEC       = 47,
    DNS_REC_NSEC3      = 50,
    DNS_REC_NSEC3PARAM = 51,
    DNS_REC_SMIMEA     = 53,
    DNS_REC_OPENPGPKEY = 61,
    DNS_REC_SVCB       = 64,
    DNS_REC_HTTPS      = 65,
    DNS_REC_PTR        = 12,
    DNS_REC_RP         = 17,
    DNS_REC_RRSIG      = 46,
    DNS_REC_SIG        = 24,
    DNS_REC_SOA        = 6,
    DNS_REC_SRV        = 33,
    DNS_REC_SSHFP      = 44,
    DNS_REC_TA         = 32768,
    DNS_REC_TKEY       = 249,
    DNS_REC_TLSA       = 52,
    DNS_REC_TSIG       = 250,
    DNS_REC_TXT        = 16,
    DNS_REC_URI        = 256
} dns_record_type;

typedef enum {
    DNS_SECTION_QUESTION   = 0,
    DNS_SECTION_ANSWER     = 1,
    DNS_SECTION_AUTHORITY  = 2,
    DNS_SECTION_ADDITIONAL = 3
} dns_section_t;

typedef enum {
    DNS_CLS_IN          = 1,
    DNS_CLS_CH          = 3,
    DNS_CLS_HS          = 4,
    DNS_CLS_QCLASS_NONE = 254,
    DNS_CLS_QCLASS_ANY  = 255
} dns_class;

typedef enum {
    DNS_RCODE_NOERROR   = 0,
    DNS_RCODE_FORMERR   = 1,
    DNS_RCODE_SERVFAIL  = 2,
    DNS_RCODE_NXDOMAIN  = 3,
    DNS_RCODE_NOTIMP    = 4,
    DNS_RCODE_REFUSED   = 5,
    DNS_RCODE_YXDOMAIN  = 6,
    DNS_RCODE_YXRRSET   = 7,
    DNS_RCODE_NOTAUTH   = 9,
    DNS_RCODE_NOTZONE   = 10,
    DNS_RCODE_BADVERS   = 16,
    DNS_RCODE_BADKEY    = 17,
    DNS_RCODE_BADTIME   = 18,
    DNS_RCODE_BADMODE   = 19,
    DNS_RCODE_BADNAME   = 20,
    DNS_RCODE_BADALG    = 21,
    DNS_RCODE_BADTRUNC  = 22,
    DNS_RCODE_BADCOOKIE = 23
} dns_rcode;

typedef enum {
    DNS_OPCODE_QUERY  = 0,
    DNS_OPCODE_IQUERY = 1,
    DNS_OPCODE_STATUS = 2,
    DNS_OPCODE_NOTIFY = 4,
    DNS_OPCODE_UPDATE = 5
} dns_opcode;

typedef struct {
    uint16_t id;
    bool     rd;
    bool     tc;
    bool     aa;
    uint8_t  opcode;
    bool     qr;
    uint8_t  rcode;
    bool     ad;
    bool     z;
    bool     cd;
    bool     ra;

    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;

} dns_header_t;

typedef struct {
    uint8_t name[0xFF];
    uint8_t length;
} dns_name_t;

typedef struct {
    dns_name_t      name;
    dns_record_type type;
    unsigned int class;
} dns_question_t;

typedef struct {
    dns_header_t   header;
    dns_question_t question;
} dns_head_t;

typedef struct {
    dns_name_t name;
    uint16_t   type;
    uint16_t class;
    uint32_t ttl;
    uint16_t length;
    union {
        uint8_t        *raw;
        dns_name_t      name;
        struct in_addr  in_addr;
        struct in6_addr in6_addr;
    } data;
} dns_record_t;

typedef struct {
    dns_record_t ans[0x100];
    dns_record_t auth[0x100];
    dns_record_t add[0x100];
} dns_filtered_body_t;

typedef struct {
    dns_head_t          head;
    dns_filtered_body_t body;
} dns_pkt_t;

typedef struct {
    uint8_t  length;
    uint8_t *data;
} dns_character_string_ptr_t;

typedef struct {
    uint16_t   preference;
    dns_name_t name;
} dns_mx_t;

typedef struct {
    uint8_t  flags;
    uint8_t  taglen;
    uint8_t *tag;
    uint8_t *value;
} dns_caa_t;

dns_record_type dns_str_to_record_type(const char *str);

bool dns_str2rcode(char *str, dns_rcode *code);

const char *dns_class2str(dns_class cls);

const char *dns_opcode2str(dns_opcode opcode);

const char *dns_rcode2str(dns_rcode rcode);

const char *dns_record_type2str(dns_record_type type);

int dns_str2namebuf(const char *name, uint8_t *buffer);

uint16_t dns_question_size(dns_name_t *name);

uint16_t dns_question_create_from_name(uint8_t *buffer, dns_name_t *name,
                                       dns_record_type type, uint16_t id);

bool dns_parse_question(uint8_t *buf, size_t len, dns_head_t *head,
                        uint8_t **body_begin);

int dns_question_create(uint8_t *buffer, char *name, dns_record_type type,
                        uint16_t id);

bool dns_send_question(uint8_t *buffer, char *name, dns_record_type type,
                       uint16_t id, int fd, struct sockaddr_storage *addr);

/**
 * Check whether two DNS names are equal (case-insensitive).
 *
 * @param name1 Valid DNS name 1.
 * @param name2 Valid DNS name 2.
 * @return The result of the comparison as a boolean.
 */
bool dns_names_eq(dns_name_t *name1, dns_name_t *name2);

bool dns_raw_names_eq(dns_name_t *name1, dns_name_t *name2);

bool dns_parse_record_raw(uint8_t *begin, uint8_t *buf, const uint8_t *end,
                          uint8_t **next, dns_record_t *record);

bool dns_parse_record(uint8_t *begin, uint8_t *buf, const uint8_t *end,
                      uint8_t **next, dns_record_t *record);

bool dns_parse_body(uint8_t *buf, uint8_t *begin, const uint8_t *end,
                    dns_pkt_t *packet);

bool dns_parse_reply(uint8_t *buf, size_t len, dns_pkt_t *packet);

void dns_buf_set_qr(uint8_t *buf, bool value);

void dns_buf_set_rd(uint8_t *buf, bool value);

void dns_buf_set_rcode(uint8_t *buf, uint8_t code);

void dns_send_reply(uint8_t *buffer, size_t len, int fd,
                    struct sockaddr_storage *addr);

bool dns_create_reply(uint8_t *buffer, size_t *len, char *name,
                      dns_record_type type, uint16_t id, dns_rcode code);

size_t dns_print_readable(char **buf, size_t buflen, const uint8_t *source,
                          size_t len, bool is_name);

/**
 * @param buf_len could be 0xFF*4
 */
void dns_name2str(dns_name_t *name, char *buf, size_t buf_len);

void dns_question2str(dns_question_t *question, char *buf, size_t len);

/**
 * @param buf_len could be 0xFFFF0
 */
size_t dns_raw_record_data2str(dns_record_t *record, uint8_t *begin,
                               uint8_t *end, bool put_quotes, char *buf,
                               size_t buf_len);

dns_section_t dns_get_section(uint16_t index, dns_header_t *header);

char *dns_section2str(dns_section_t section);

char *dns_section2str_lower_plural(dns_section_t section);

bool dns_in_zone(dns_name_t *name, dns_name_t *zone);

void dns_print_packet(FILE *f, dns_pkt_t *packet, uint8_t *begin, size_t len,
                      uint8_t *next);

uint8_t dns_ip_octet2label(uint8_t *dst, uint8_t octet);

bool dns_ip2ptr(const char *qname, dns_name_t *name);

#endif
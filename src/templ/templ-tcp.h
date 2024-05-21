#ifndef TEMPL_TCP_H
#define TEMPL_TCP_H

#include <stdio.h>

#include "templ-pkt.h"
#include "../util-misc/cross.h"
#include "../massip/massip-addr.h"

struct TemplateOptions;

#define TCP_FLAG_CWR 0B10000000
#define TCP_FLAG_ECE 0B01000000
#define TCP_FLAG_URG 0B00100000
#define TCP_FLAG_ACK 0B00010000
#define TCP_FLAG_PSH 0B00001000
#define TCP_FLAG_RST 0B00000100
#define TCP_FLAG_SYN 0B00000010
#define TCP_FLAG_FIN 0B00000001

#define TCP_SEQNO(px,i) ((px)[(i)+ 4]<<24|(px)[(i)+5]<<16|(px)[(i)+6]<< 8|(px)[(i)+ 7])
#define TCP_ACKNO(px,i) ((px)[(i)+ 8]<<24|(px)[(i)+9]<<16|(px)[(i)+10]<<8|(px)[(i)+11])
#define TCP_FLAGS(px,i) ((px)[(i)+13])
#define TCP_WIN(px,i)   ((px)[(i)+14]<< 8|(px)[(i)+15]) /*calc TCP window size*/

#define TCP_HAS_FLAG(px,i,flag) ((TCP_FLAGS((px),(i)) & (flag)) == (flag))

#define TCP_OPT_TYPE_EOL            0
#define TCP_OPT_TYPE_NOP            1
#define TCP_OPT_TYPE_MSS            2
#define TCP_OPT_TYPE_WS             3
#define TCP_OPT_TYPE_SACK_PERM      4
#define TCP_OPT_TYPE_SACK           5
#define TCP_OPT_TYPE_TS             8
#define TCP_OPT_TYPE_MD5            19
#define TCP_OPT_TYPE_UTO            28
#define TCP_OPT_TYPE_AO             29
#define TCP_OPT_TYPE_EXP1           253
#define TCP_OPT_TYPE_EXP2           254

#define TCP_OPT_LEN_EOL             1
#define TCP_OPT_LEN_NOP             1
#define TCP_OPT_LEN_MSS             4
#define TCP_OPT_LEN_WS              3
#define TCP_OPT_LEN_SACK_PERM       2
#define TCP_OPT_LEN_TS              10
#define TCP_OPT_LEN_MD5             18
#define TCP_OPT_LEN_UTO             4

#define TCP_DEFAULT_MSS             1460


/**
 * Called during configuration, to apply all the various changes the
 * user asked for on the command-line, such as optioms like:
 * --tcp-mss 1460
 * --tcp-sackperm
 * --tcp-wscale 3
 */
void
templ_tcp_apply_options(unsigned char **inout_buf, size_t *inout_length,
                  const struct TemplateOptions *templ_opts);

/**
 * Set's the TCP "window" field in raw.
 */
void
tcp_set_window(unsigned char *px, size_t px_length, unsigned window);


/**
 * Create a TCP packet containing a payload, based on the original
 * template used for the SYN
 */
size_t
tcp_create_by_template(
        const struct TemplatePacket *tmpl,
        ipaddress ip_them, unsigned port_them,
        ipaddress ip_me, unsigned port_me,
        unsigned seqno, unsigned ackno,
        unsigned flags,
        const unsigned char *payload, size_t payload_length,
        unsigned char *px, size_t px_length);

/**
 * This is a wrapped func that uses global_tmplset to create tcp packet.
*/
size_t
tcp_create_packet(
        ipaddress ip_them, unsigned port_them,
        ipaddress ip_me, unsigned port_me,
        unsigned seqno, unsigned ackno,
        unsigned flags,
        const unsigned char *payload, size_t payload_length,
        unsigned char *px, size_t px_length);

/*Convert TCP flags into string*/
void
tcp_flags_to_string(unsigned flag, char *string, size_t str_len);

unsigned
tcp_get_mss(const unsigned char *buf, size_t length, bool *is_found);

unsigned
tcp_get_wscale(const unsigned char *buf, size_t length, bool *is_found);

unsigned
tcp_get_sackperm(const unsigned char *buf, size_t length, bool *is_found);

int templ_tcp_selftest();

#endif

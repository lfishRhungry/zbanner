#ifndef STACK_TCP_CORE_H
#define STACK_TCP_CORE_H

#include "stack-queue.h"
#include "../util-misc/cross.h"
#include "../output-modules/output-modules.h"
#include "../templ/templ-tcp.h"
#include "../massip/massip-addr.h"
#include "../proto/proto-datapass.h"
#include "../timeout/event-timeout.h"
#include "../probe-modules/probe-modules.h"

enum TCP_What {
    TCP_WHAT_TIMEOUT, /*The connection time is expired*/
    TCP_WHAT_SYNACK,  /*Received SYN-ACK*/
    TCP_WHAT_RST,     /*Received RST*/
    TCP_WHAT_FIN,     /*Received FIN*/
    TCP_WHAT_ACK,     /*Received ACK (ignored data)*/
    TCP_WHAT_DATA,    /*Received DATA (just focus data)*/
};

enum   App_State;
enum   App_Event;
enum   SOCK_Res;

struct StackHandler;
struct TCP_Control_Block;
struct TCP_ConnectionTable;


struct TCP_ConnectionTable *
tcpcon_create_table(size_t entry_count,
    struct stack_t *stack,
    struct TemplatePacket *tcp_template,
    struct TemplatePacket *syn_template,
    struct TemplatePacket *rst_template,
    struct Output *out,
    unsigned timeout,
    uint64_t entropy);

void
tcpcon_destroy_table(struct TCP_ConnectionTable *tcpcon);


/**
 * Handle timeout event  for now time.
 * Logically, we need wall time here.
 * 
 * @param tcpcon tcp conn table
 * @param secs now time secs
 * @param usecs now time usecs
*/
void
tcpcon_timeouts(struct TCP_ConnectionTable *tcpcon, unsigned secs, unsigned usecs);

void
stack_incoming_tcp(
    struct TCP_ConnectionTable *tcpcon,
    struct TCP_Control_Block *entry,
    enum TCP_What what, 
    const unsigned char *payload,
    size_t payload_length,
    unsigned secs, unsigned usecs,
    unsigned seqno_them, unsigned ackno_them);


struct TCP_Control_Block *
tcpcon_lookup_tcb(
    struct TCP_ConnectionTable *tcpcon,
    ipaddress ip_src, ipaddress ip_dst,
    unsigned port_src, unsigned port_dst);

/**
 * Create a new TCB (TCP control block. It's created only in two places,
 * either because we've initiated an outbound TCP connection, or we've
 * received incoming SYN-ACK from a probe.
 * @param mss the mss of in synack. set it to 0 if non-mss then we use default 1460
 */
struct TCP_Control_Block *
tcpcon_create_tcb(
    struct TCP_ConnectionTable *tcpcon,
    ipaddress ip_src, ipaddress ip_dst,
    unsigned port_src, unsigned port_dst,
    unsigned my_seqno, unsigned their_seqno,
    unsigned ttl, unsigned mss,
    const struct ProbeModule *probe,
    unsigned secs, unsigned usecs);

/**
 * get active tcb count
*/
uint64_t
tcpcon_active_count(struct TCP_ConnectionTable *tcpcon);


enum SOCK_Res
tcpapi_set_timeout(struct StackHandler *socket, unsigned secs, unsigned usecs);

/**
 * Change from the "send" state to the "receive" state.
 * Has no effect if in any state other than "send".
 * This is none-blocking, an event will be triggered
 * later that has the data.
 */
enum SOCK_Res
tcpapi_recv(struct StackHandler *socket);

/**
 * just send data but not close
*/
enum SOCK_Res
tcpapi_send_data(struct StackHandler *socket, const void *buf,
    size_t length, unsigned is_dynamic);


enum SOCK_Res
tcpapi_change_app_state(struct StackHandler *socket, enum App_State new_app_state);


/**
 * Send RST and del TCB to close the conn quickly.
 * Call this only when the upper-layer probe want to close it actively.
*/
enum SOCK_Res
tcpapi_close(struct StackHandler *socket);

/**
 * Media between Probe and our simplified TCP stack
 */
void
application_event(struct StackHandler *socket, enum App_Event cur_event,
    const void *payload, size_t payload_length);

#endif

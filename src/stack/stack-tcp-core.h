#ifndef STACK_TCP_CORE_H
#define STACK_TCP_CORE_H

#include "stack-queue.h"
#include "../util/bool.h"
#include "../output/output.h"
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
    TCP_WHAT_CLOSE,   /*We want to close the connection*/
};

enum TCB_result {
    TCB__okay,
    TCB__destroyed
};

enum   App_State;
enum   App_Event;
struct TCP_Control_Block;
struct TCP_ConnectionTable;
struct stack_handle_t;



/**
 * Create a TCP connection table (to store TCP control blocks) with
 * the desired initial size.
 *
 * @param entry_count
 *      A hint about the desired initial size. This should be about twice
 *      the number of outstanding connections, so you should base this number
 *      on your transmit rate (the faster the transmit rate, the more
 *      outstanding connections you'll have). This function will automatically
 *      round this number up to the nearest power of 2, or round it down
 *      if it causes malloc() to not be able to allocate enough memory.
 * @param entropy
 *      Seed for syn-cookie randomization
 */
struct TCP_ConnectionTable *
tcpcon_create_table(size_t entry_count,
    struct stack_t *stack,
    struct TemplatePacket *pkt_template,
    struct Output *out,
    unsigned timeout,
    uint64_t entropy);

/**
 * Gracefully destroy a TCP connection table. This is the last chance for any
 * partial banners (like HTTP server version) to be sent to the output. At the
 * end of a scan, you'll see a bunch of banners all at once due to this call.
 *
 * @param tcpcon
 *      A TCP connection table created with a matching call to
 *      'tcpcon_create_table()'.
 */
void
tcpcon_destroy_table(struct TCP_ConnectionTable *tcpcon);


void
tcpcon_timeouts(struct TCP_ConnectionTable *tcpcon, unsigned secs, unsigned usecs);

enum TCB_result
stack_incoming_tcp(struct TCP_ConnectionTable *tcpcon, struct TCP_Control_Block *entry,
    enum TCP_What what, 
    const unsigned char *payload, size_t payload_length,
    unsigned secs, unsigned usecs,
    unsigned seqno_them, unsigned ackno_them);


/**
 * Lookup a connection record based on IP/ports.
 */
struct TCP_Control_Block *
tcpcon_lookup_tcb(struct TCP_ConnectionTable *tcpcon,
    ipaddress ip_src, ipaddress ip_dst,
    unsigned port_src, unsigned port_dst);

/**
 * Create a new TCB (TCP control block. It's created only in two places,
 * either because we've initiated an outbound TCP connection, or we've
 * received incoming SYN-ACK from a probe.
 */
struct TCP_Control_Block *
tcpcon_create_tcb(
    struct TCP_ConnectionTable *tcpcon,
    ipaddress ip_src, ipaddress ip_dst,
    unsigned port_src, unsigned port_dst,
    unsigned my_seqno, unsigned their_seqno,
    unsigned ttl,
    const struct ProbeModule *probe,
    unsigned secs, unsigned usecs);


void
tcpcon_send_RST(struct TCP_ConnectionTable *tcpcon,
                ipaddress ip_me, ipaddress ip_them,
                unsigned port_me, unsigned port_them,
                uint32_t seqno_them, uint32_t ackno_them);


/**
 * Set a new default timeout.
 */
int
tcpapi_set_timeout(struct stack_handle_t *socket, unsigned secs, unsigned usecs);

/**
 * Change from the "send" state to the "receive" state.
 * Has no effect if in any state other than "send".
 * This is none-blocking, an event will be triggered
 * later that has the data.
 */
int
tcpapi_recv(struct stack_handle_t *socket);

/**
 * !cannot do sending data and closing at same time
 * if set closing, we would ignore the data.
*/
int
tcpapi_send(struct stack_handle_t *socket,
            const void *buf, size_t length,
            unsigned is_dynamic, unsigned is_close);

/**
 * Re-connect to the target, same IP and port, creating a new connection
 * from a different port on this side.
 */
int
tcpapi_reconnect(struct stack_handle_t *old_socket,
                 struct ProbeModule *new_probe,
                 enum App_State new_app_state);

/**
 * The "app state" variable is stored opaquely in the `tcb` structure, so
 * to reset it, we need an access function.
 */
unsigned
tcpapi_change_app_state(struct stack_handle_t *socket, enum App_State new_app_state);


/** Perform the sockets half-close function (calling `close()`). This
 * doesn't actually get rid of the socket, but only stops sending.
 * It sends a FIN packet to the other side, and transitions to the
 * TCP CLOSE-WAIT state.
 * The socket will continue to receive from the opposing side until they
 * give us a FIN packet. */
int
tcpapi_close(struct stack_handle_t *socket);

/**
 * This is the interface between the underlying custom TCP/IP stack and
 * the rest of masscan. SCRIPTING will eventually go in here.
 */
unsigned
application_event(struct stack_handle_t *socket,
                  enum App_State state, enum App_Event event,
                  const struct ProbeModule *probe,
                  const void *payload, size_t payload_length);

#endif

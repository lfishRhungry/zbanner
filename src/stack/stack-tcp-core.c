/*
 * This is the core TCP layer in the stack. It's notified of incoming
 * IP datagrams containing TCP protocols. This is where the TCP state
 * diagram is handled.
 *
 *                                    
 *                              +---------+ ---------\      active OPEN  
 *                              |  CLOSED |            \    -----------  
 *                              +---------+<---------\   \   create TCB  
 *                                |     ^              \   \  snd SYN    
 *                   passive OPEN |     |   CLOSE        \   \           
 *                   ------------ |     | ----------       \   \         
 *                    create TCB  |     | delete TCB         \   \       
 *                                V     |                      \   \     
 *                              +---------+            CLOSE    |    \   
 *                              |  LISTEN |          ---------- |     |  
 *                              +---------+          delete TCB |     |  
 *                   rcv SYN      |     |     SEND              |     |  
 *                  -----------   |     |    -------            |     V  
 * +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
 * |         |<-----------------           ------------------>|         |
 * |   SYN   |                    rcv SYN                     |   SYN   |
 * |   RCVD  |<-----------------------------------------------|   SENT  |
 * |         |                    snd ACK                     |         |
 * |         |------------------           -------------------|         |
 * +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
 *   |           --------------   |     |   -----------                  
 *   |                  x         |     |     snd ACK                    
 *   |                            V     V                                
 *   |  CLOSE                   +---------+                              
 *   | -------                  |  ESTAB  |                              
 *   | snd FIN                  +---------+                              
 *   |                   CLOSE    |     |    rcv FIN                     
 *   V                  -------   |     |    -------                     
 * +---------+          snd FIN  /       \   snd ACK          +---------+
 * |  FIN    |<-----------------           ------------------>|  CLOSE  |
 * | WAIT-1  |------------------                              |   WAIT  |
 * +---------+          rcv FIN  \                            +---------+
 *   | rcv ACK of FIN   -------   |                            CLOSE  |  
 *   | --------------   snd ACK   |                           ------- |  
 *   V        x                   V                           snd FIN V  
 * +---------+                  +---------+                   +---------+
 * |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
 * +---------+                  +---------+                   +---------+
 *   |                rcv ACK of FIN |                 rcv ACK of FIN |  
 *   |  rcv FIN       -------------- |    Timeout=2MSL -------------- |  
 *   |  -------              x       V    ------------        x       V  
 *    \ snd ACK                 +---------+delete TCB         +---------+
 *     ------------------------>|TIME WAIT|------------------>| CLOSED  |
 *                              +---------+                   +---------+
 *
 */

/**
 * !BUT
 * For code clean, fast scanning and achieve our target, I improve(or downgrade)
 * the TCP stack(FSM) to a more simpler one with just 3 states.
*/
#include "stack-tcp-core.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <stdarg.h>

#include "stack-queue.h"
#include "stack-src.h"
#include "../massip/massip-cookie.h"
#include "../timeout/event-timeout.h"
#include "../rawsock/rawsock.h"
#include "../util-out/logger.h"
#include "../templ/templ-tcp.h"
#include "../pixie/pixie-timer.h"
#include "../util-data/safe-string.h"
#include "../globals.h"
#include "../crypto/crypto-base64.h"
#include "../util-data/fine-malloc.h"
#include "../util-out/errormsg.h"


#ifdef _MSC_VER
#pragma warning(disable:4204)
#define snprintf _snprintf
#pragma warning(disable:4996)
#endif


struct TCP_Segment {
    unsigned seqno;
    unsigned char *buf;
    size_t length;
    unsigned is_dynamic:1;
    struct TCP_Segment *next;
};

enum Tcp_State{
    STATE_SYN_SENT = 0,       /* init state, must be zero */
    STATE_ESTABLISHED_SEND,   /* sending now */
    STATE_ESTABLISHED_RECV,   /* want to receive */
};

/**
 * Abstract TCP data exchange to uppper application service State and Event to
 * fit our design and interfaces.
*/
enum App_State{
    APP_STATE_INIT = 0,       /*init state, must be zero*/
    APP_STATE_RECV_HELLO,     /*wait for hello*/
    APP_STATE_RECV_NEXT,      /*wait for payload*/
    APP_STATE_SEND_FIRST,     /*our turn to say hello*/
    APP_STATE_SEND_NEXT,      /*our turn to send payload*/
};

enum App_Event {
    APP_WHAT_CONNECTED,       /*conn has been established*/
    APP_WHAT_RECV_TIMEOUT,    /*for hello waiting*/
    APP_WHAT_RECV_PAYLOAD,
    APP_WHAT_SENDING,
    APP_WHAT_SEND_SENT,       /*our data has been sent and acked*/
};

struct TCP_Control_Block
{
    ipaddress                         ip_me;
    ipaddress                         ip_them;
    unsigned short                    port_me;
    unsigned short                    port_them;
    union {
        uint32_t                      seqno_me;          /* next seqno I will use for transmit */
        uint32_t                      ackno_them;
    };
    union {
        uint32_t                      seqno_them;        /* the next seqno I expect to receive */
        uint32_t                      ackno_me;
    };

    /*conn's initial seqno for debugging */
    uint32_t                          seqno_me_first;
    uint32_t                          seqno_them_first;

    struct TCP_Segment               *segments;
    enum Tcp_State                    tcpstate;
    enum App_State                    app_state;
    unsigned char                     ttl;
    unsigned char                     syns_sent;         /* reconnect */
    unsigned short                    mss;               /* maximum segment size 1460 TODO: maybe negotiate it */
    time_t                            when_created;
    unsigned                          is_active:1;       /*in-use/allocated or to be del soon*/

    const struct ProbeModule         *probe;
    struct ProbeState                 probe_state;

    struct TimeoutEntry               timeout[1];        /*only one for this TCB*/
    struct TCP_Control_Block         *next;
};

struct TCP_ConnectionTable {
    struct TCP_Control_Block        **entries;
    struct TCP_Control_Block         *freed_list;

    struct TemplatePacket            *tcp_template;
    struct TemplatePacket            *syn_template;
    struct Timeouts                  *timeouts;
    struct stack_t                   *stack;
    struct Output                    *out;

    unsigned                          timeout_conn;
    unsigned                          count;
    unsigned                          mask;
    unsigned                          src_port_start;

    uint64_t                          active_count;
    uint64_t                          entropy;
};

enum {
    SOCKERR_NONE  = 0,   /* no error */
    SOCKERR_EBADF = 10,  /* bad socket descriptor */
};

struct stack_handle_t {
    struct TCP_ConnectionTable *tcpcon;
    struct TCP_Control_Block   *tcb;
    unsigned secs;
    unsigned usecs;
};

enum DestroyReason {
    Reason_Timeout   = 1,
    Reason_FIN       = 2,
    Reason_RST       = 3,
    Reason_Foo       = 4,
    Reason_Shutdown  = 5,
    Reason_StateDone = 6,

};

uint64_t tcpcon_active_tcb(struct TCP_ConnectionTable *tcpcon)
{
    return tcpcon->active_count;
}

/***************************************************************************
 * DEBUG: when printing debug messages (-d option), this prints a string
 * for the given state.
 ***************************************************************************/
static const char *
tcp_state_to_string(enum Tcp_State state)
{
    switch (state) {
        case STATE_SYN_SENT:            return "SYN_SENT";
        case STATE_ESTABLISHED_SEND:    return "ESTABLISHED_SEND";
        case STATE_ESTABLISHED_RECV:    return "ESTABLISHED_RECV";

        default:
            return "UNKN_STATE";
    }
}

static void
vLOGtcb(const struct TCP_Control_Block *tcb, int dir, const char *fmt, va_list marker)
{
    char sz[256];
    ipaddress_formatted_t fmt1 = ipaddress_fmt(tcb->ip_them);

    snprintf(sz, sizeof(sz), "[%s:%u %4u,%4u] %s:%5u [%4u,%4u] {%s} ",
             fmt1.string, tcb->port_them,
             tcb->seqno_them - tcb->seqno_them_first,
             tcb->ackno_me - tcb->seqno_them_first,
             (dir > 0) ? "-->" : "<--",
             tcb->port_me,
             tcb->seqno_me - tcb->seqno_me_first,
             tcb->ackno_them - tcb->seqno_me_first,
             tcp_state_to_string(tcb->tcpstate)
             );
    sz[255] = '\0';
    if (dir == 2) {
        char *brace = strchr(sz, '{');
        memset(sz, ' ', brace-sz);
    }
    fprintf(stderr, "%s", sz);
    vfprintf(stderr, fmt, marker);
    fflush(stderr);
}

static int is_tcp_debug = 0;

static void
LOGtcb(const struct TCP_Control_Block *tcb, int dir, const char *fmt, ...)
{
    va_list marker;

    if (!is_tcp_debug)
        return;
    va_start(marker, fmt);
    vLOGtcb(tcb, dir, fmt, marker);
    va_end(marker);
}



/***************************************************************************
 * Process all events, up to the current time, that need timing out.
 ***************************************************************************/
void
tcpcon_timeouts(struct TCP_ConnectionTable *tcpcon, unsigned secs, unsigned usecs)
{
    uint64_t timestamp = TICKS_FROM_TV(secs, usecs);

    for (;;) {
        struct TCP_Control_Block *tcb;
        enum TCB_result x;

        tcb = (struct TCP_Control_Block *)timeouts_remove(tcpcon->timeouts,
                                                          timestamp);

        if (tcb == NULL)
            break;

        x = stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_TIMEOUT,
            0, 0,
            secs, usecs,
            tcb->seqno_them,
            tcb->ackno_them);

        /**
         * If the TCB hasn't been destroyed, then we need to make sure there is
         * a timeout associated with it.
         * This is important for conn maintenance like:
         * resending packets,
         * deleting expired conns,
         * etc.
         * */
        if (x != TCB__destroyed && timeout_is_unlinked(tcb->timeout)) {
            timeouts_add(tcpcon->timeouts,
                         tcb->timeout,
                         offsetof(struct TCP_Control_Block, timeout),
                         TICKS_FROM_TV(secs+2, usecs));
        }
    }
}

struct TCP_ConnectionTable *
tcpcon_create_table(size_t entry_count,
    struct stack_t *stack,
    struct TemplatePacket *tcp_template,
    struct TemplatePacket *syn_template,
    struct Output *out,
    unsigned connection_timeout,
    uint64_t entropy)
{
    struct TCP_ConnectionTable *tcpcon = CALLOC(1, sizeof(*tcpcon));

    /* Find nearest power of 2 to the tcb count, but don't go
     * over the number 16-million */
    {
        size_t new_entry_count;
        new_entry_count = 1;
        while (new_entry_count < entry_count) {
            new_entry_count *= 2;
            if (new_entry_count == 0) {
                new_entry_count = (1<<24);
                break;
            }
        }
        if (new_entry_count > (1<<24))
            new_entry_count = (1<<24);
        if (new_entry_count < (1<<10))
            new_entry_count = (1<<10);
        entry_count = new_entry_count;
    }

    /* Create the table. If we can't allocate enough memory, then shrink
     * the desired size of the table */
    while (tcpcon->entries == 0) {
        tcpcon->entries = MALLOC(entry_count * sizeof(*tcpcon->entries));
        if (tcpcon->entries == NULL) {
            entry_count >>= 1;
        }
    }
    memset(tcpcon->entries, 0, entry_count * sizeof(*tcpcon->entries));

    tcpcon->timeout_conn = connection_timeout;
    if (tcpcon->timeout_conn == 0)
        tcpcon->timeout_conn = 30; /* half a minute before destroying tcb */

    tcpcon->tcp_template         = tcp_template;
    tcpcon->syn_template         = syn_template;
    tcpcon->entropy              = entropy;
    tcpcon->count                = (unsigned)entry_count;
    tcpcon->mask                 = (unsigned)(entry_count-1);
    tcpcon->timeouts             = timeouts_create(TICKS_FROM_SECS(time(0)));
    tcpcon->stack                = stack;
    tcpcon->out                  = out;
    tcpcon->src_port_start       = stack->src->port.first;

    return tcpcon;
}

static int TCB_EQUALS(const struct TCP_Control_Block *lhs, const struct TCP_Control_Block *rhs)
{
    if (lhs->port_me != rhs->port_me || lhs->port_them != rhs->port_them)
        return 0;
    if (lhs->ip_me.version != rhs->ip_me.version)
        return 0;
    if (lhs->ip_me.version == 6) {
        if (memcmp(&lhs->ip_me.ipv6, &rhs->ip_me.ipv6, sizeof(rhs->ip_me.ipv6)) != 0)
            return 0;
        if (memcmp(&lhs->ip_them.ipv6, &rhs->ip_them.ipv6, sizeof(rhs->ip_them.ipv6)) != 0)
            return 0;
    } else {
        if (lhs->ip_me.ipv4 != rhs->ip_me.ipv4)
            return 0;
        if (lhs->ip_them.ipv4 != rhs->ip_them.ipv4)
            return 0;
    }

    return 1;
}

/***************************************************************************
 ***************************************************************************/
static void
_tcb_change_state_to(struct TCP_Control_Block *tcb, enum Tcp_State new_state) {

    LOGtcb(tcb, 2, "to {%s}\n", tcp_state_to_string(new_state));
    tcb->tcpstate = new_state;
}

/***************************************************************************
 * Destroy a TCP connection entry. We have to unlink both from the
 * TCB-table as well as the timeout-table.
 ***************************************************************************/
static void
tcpcon_destroy_tcb(struct TCP_ConnectionTable *tcpcon,
    struct TCP_Control_Block *tcb,
    enum DestroyReason reason)
{
    unsigned index;
    struct TCP_Control_Block **r_entry;
    
    UNUSEDPARM(reason);

    index = get_cookie(tcb->ip_me, tcb->port_me, 
        tcb->ip_them, tcb->port_them, 
        tcpcon->entropy);
    
    r_entry = &tcpcon->entries[index & tcpcon->mask];
    while (*r_entry && *r_entry != tcb)
        r_entry = &(*r_entry)->next;

    if (*r_entry == NULL) {
        LOG(LEVEL_WARNING, "tcb: double free\n");
        return;
    }

    LOGtcb(tcb, 2, "--DESTROYED--\n");

    while (tcb->segments) {
        struct TCP_Segment *seg = tcb->segments;
        tcb->segments           = seg->next;

        if (seg->is_dynamic) {
            free(seg->buf);
            seg->buf = 0;
        }

        free(seg);
    }

    /*
     * Unlink this from the timeout system.
     */
    timeout_unlink(tcb->timeout);

    tcb->ip_them.ipv4 = (unsigned)~0;
    tcb->port_them    = (unsigned short)~0;
    tcb->ip_me.ipv4   = (unsigned)~0;
    tcb->port_me      = (unsigned short)~0;

    tcb->is_active = 0;

    /*do connection close for probe*/
    struct ProbeTarget target = {
        .ip_them   = tcb->ip_them,
        .port_them = tcb->port_them,
        .ip_me     = tcb->ip_me,
        .port_me   = tcb->port_me,
        .cookie    = 0,               /*ProbeType State doesn't need cookie*/
        .index     = tcb->port_me-tcpcon->src_port_start,
    };
    tcb->probe->conn_close_cb(&tcb->probe_state, &target);


    (*r_entry) = tcb->next;
    tcb->next  = tcpcon->freed_list;
    tcpcon->freed_list = tcb;
    tcpcon->active_count--;
}

void
tcpcon_destroy_table(struct TCP_ConnectionTable *tcpcon)
{
    unsigned i;

    if (tcpcon == NULL)
        return;

    for (i=0; i<=tcpcon->mask; i++) {
        while (tcpcon->entries[i]) {
            tcpcon_destroy_tcb(tcpcon, tcpcon->entries[i], Reason_Shutdown);
        }
    }

    while (tcpcon->freed_list) {
        struct TCP_Control_Block *tcb = tcpcon->freed_list;
        tcpcon->freed_list = tcb->next;
        free(tcb);
    }

    free(tcpcon->entries);
    free(tcpcon);
}


/***************************************************************************
 * Called when we receive a "SYN-ACK" packet with the correct SYN-cookie.
 ***************************************************************************/
struct TCP_Control_Block *
tcpcon_create_tcb(
    struct TCP_ConnectionTable *tcpcon,
    ipaddress ip_me, ipaddress ip_them,
    unsigned port_me, unsigned port_them,
    unsigned seqno_me, unsigned seqno_them,
    unsigned ttl,
    const struct ProbeModule *probe,
    unsigned secs, unsigned usecs)
{
    unsigned index;
    struct TCP_Control_Block tmp;
    struct TCP_Control_Block *tcb;


    assert(ip_me.version != 0 && ip_them.version != 0);

    tmp.ip_me     = ip_me;
    tmp.ip_them   = ip_them;
    tmp.port_me   = (unsigned short)port_me;
    tmp.port_them = (unsigned short)port_them;

    index = get_cookie(ip_me, port_me, ip_them, port_them, tcpcon->entropy);
    tcb   = tcpcon->entries[index & tcpcon->mask];

    while (tcb && !TCB_EQUALS(tcb, &tmp)) {
        tcb = tcb->next;
    }

    if (tcb != NULL) {
        /* If it already exists, just return the existing one */
        return tcb;
    }

    /* Allocate a new TCB, using a pool */
    if (tcpcon->freed_list) {
        tcb = tcpcon->freed_list;
        tcpcon->freed_list = tcb->next;
    } else {
        tcb = MALLOC(sizeof(*tcb));
    }
    memset(tcb, 0, sizeof(*tcb));

    tcb->next = tcpcon->entries[index & tcpcon->mask];
    tcpcon->entries[index & tcpcon->mask] = tcb;

    tcb->ip_me            = ip_me;
    tcb->ip_them          = ip_them;
    tcb->port_me          = (uint16_t)port_me;
    tcb->port_them        = (uint16_t)port_them;
    tcb->seqno_me         = seqno_me;
    tcb->seqno_them       = seqno_them;
    tcb->seqno_me_first   = seqno_me;
    tcb->seqno_them_first = seqno_them;
    tcb->when_created     = global_now;
    tcb->ttl              = (unsigned char)ttl;
    tcb->mss              = TCP_DEFAULT_MSS;
    tcb->probe            = probe;

    /* Insert the TCB into the timeout. A TCB must always have a timeout
     * active to insure to be deleted. */
    timeout_init(tcb->timeout);
    timeouts_add(tcpcon->timeouts, tcb->timeout,
        offsetof(struct TCP_Control_Block, timeout),
        TICKS_FROM_TV(secs+1,usecs));


    /* The TCB is now allocated/in-use */
    assert(tcb->ip_me.version != 0 && tcb->ip_them.version != 0);

    tcb->is_active = 1;
    tcpcon->active_count++;

    /*do connection init for probe*/
    struct ProbeTarget target = {
        .ip_them   = ip_them,
        .port_them = port_them,
        .ip_me     = ip_me,
        .port_me   = port_me,
        .cookie    = 0,               /*ProbeType State doesn't need cookie*/
        .index     = port_me-tcpcon->src_port_start,
    };
    probe->conn_init_cb(&tcb->probe_state, &target);

    return tcb;
}



/***************************************************************************
 ***************************************************************************/
struct TCP_Control_Block *
tcpcon_lookup_tcb(
    struct TCP_ConnectionTable *tcpcon,
    ipaddress ip_me, ipaddress ip_them,
    unsigned port_me, unsigned port_them)
{
    unsigned index;
    struct TCP_Control_Block tmp;
    struct TCP_Control_Block *tcb;

    tmp.ip_me     = ip_me;
    tmp.ip_them   = ip_them;
    tmp.port_me   = (unsigned short)port_me;
    tmp.port_them = (unsigned short)port_them;

    index = get_cookie(ip_me, port_me, ip_them, port_them, tcpcon->entropy);
    tcb   = tcpcon->entries[index & tcpcon->mask];

    while (tcb && !TCB_EQUALS(tcb, &tmp)) {
        tcb = tcb->next;
    }


    return tcb;
}


/***************************************************************************
 ***************************************************************************/
static void
tcpcon_send_packet(
    struct TCP_ConnectionTable *tcpcon,
    struct TCP_Control_Block *tcb,
    unsigned tcp_flags,
    const unsigned char *payload, size_t payload_length)
{
    struct PacketBuffer *response = 0;
    unsigned is_syn = (tcp_flags == TCP_FLAG_SYN);

    assert(tcb->ip_me.version != 0 && tcb->ip_them.version != 0);

    /* If sending an ACK, print a message */
    if ((tcp_flags & TCP_FLAG_ACK) == TCP_FLAG_ACK) {
        LOGtcb(tcb, 0, "xmit ACK ackingthem=%u\n", tcb->seqno_them-tcb->seqno_them_first);
    }

    response = stack_get_packetbuffer(tcpcon->stack);

    if (response == NULL) {
        static int is_warning_printed = 0;
        if (!is_warning_printed) {
            LOG(LEVEL_ERROR, "packet buffers empty (should be impossible)\n");
            is_warning_printed = 1;
        }
        fflush(stdout);

        /* FIXME: This would result from a bug in the code,
         * but I'm not sure what should be done in response */
        pixie_usleep(100); /* no packet available */
    }
    if (response == NULL)
        return;

    response->length = tcp_create_by_template(
        is_syn?tcpcon->syn_template:tcpcon->tcp_template,
        tcb->ip_them, tcb->port_them,
        tcb->ip_me, tcb->port_me,
        tcb->seqno_me - is_syn, tcb->seqno_them,
        tcp_flags, payload, payload_length,
        response->px, sizeof(response->px));

    stack_transmit_packetbuffer(tcpcon->stack, response);
}


/***************************************************************************
 * DEBUG: when printing debug messages (-d option), this prints a string
 * for the given state.
 ***************************************************************************/
static const char *
what_to_string(enum TCP_What state)
{
    switch (state) {
        case TCP_WHAT_TIMEOUT:  return "TIMEOUT";
        case TCP_WHAT_SYNACK:   return "SYNACK";
        case TCP_WHAT_RST:      return "RST";
        case TCP_WHAT_FIN:      return "FIN";
        case TCP_WHAT_ACK:      return "ACK";
        case TCP_WHAT_DATA:     return "DATA";
        case TCP_WHAT_CLOSE:    return "CLOSE";
        default:
            return "UNKN_WHAT";
    }
}


/***************************************************************************
 * This function could be used without TCB.
 * So we could start any conn from any TCP Conn Table.
 ***************************************************************************/
static void
tcpcon_send_raw_SYN(struct TCP_ConnectionTable *tcpcon,
                ipaddress ip_them, unsigned port_them,
                ipaddress ip_me, unsigned port_me, 
                uint32_t seqno_me)
{
    struct PacketBuffer *response = 0;
    
    assert(ip_me.version != 0 && ip_them.version != 0);

    response = stack_get_packetbuffer(tcpcon->stack);

    if (response == NULL) {
        static int is_warning_printed = 0;
        if (!is_warning_printed) {
            LOG(LEVEL_ERROR, "packet buffers empty (should be impossible)\n");
            is_warning_printed = 1;
        }
        fflush(stdout);
        
        /* FIXME: This would result from a bug in the code,
         * but I'm not sure what should be done in response */
        pixie_usleep(100); /* no packet available */
    }
    if (response == NULL)
        return;

    response->length = tcp_create_by_template(
        tcpcon->syn_template,
        ip_them, port_them,
        ip_me, port_me,
        seqno_me, 0,
        TCP_FLAG_SYN, NULL, 0,
        response->px, sizeof(response->px));

    stack_transmit_packetbuffer(tcpcon->stack, response);
}


/***************************************************************************
 * Called upon timeouts when an acknowledgement hasn't been received in
 * time. Will resend the segments.
 ***************************************************************************/
static void
_tcb_seg_resend(struct TCP_ConnectionTable *tcpcon, struct TCP_Control_Block *tcb) {
    struct TCP_Segment *seg = tcb->segments;

    if (seg) {
        /*just handle packets with data (no data could be impossible)*/
        if (!seg->length || !seg->buf) return;

        if (tcb->seqno_me != seg->seqno) {
            ERRMSG("SEQNO FAILURE diff=%d\n", tcb->seqno_me - seg->seqno);
            return;
        }

        tcpcon_send_packet(tcpcon, tcb,
                            TCP_FLAG_PSH | TCP_FLAG_ACK,
                            seg->buf, seg->length);
    }

}

/***************************************************************************
 ***************************************************************************/
static void
application_notify(struct TCP_ConnectionTable *tcpcon,
                   struct TCP_Control_Block *tcb,
                   enum App_Event event, const void *payload, size_t payload_length,
                   unsigned secs, unsigned usecs)
{
    struct stack_handle_t socket = {tcpcon, tcb, secs, usecs};

    application_event(&socket, tcb->app_state, event, tcb->probe,
        payload, payload_length);
}


/***************************************************************************
 * !cannot do sending data and closing at same time
 * if set closing, we would ignore the data.
 ***************************************************************************/
static void 
_tcb_seg_send(void *in_tcpcon, void *in_tcb, 
        const void *buf, size_t length, 
        unsigned is_dynamic) {
    
    if (!buf || !length) return;

    struct TCP_ConnectionTable    *tcpcon        = (struct TCP_ConnectionTable *)in_tcpcon;
    struct TCP_Control_Block      *tcb           = (struct TCP_Control_Block *)in_tcb;
    unsigned                       seqno         = tcb->seqno_me;
    size_t                         length_more   = 0;
    struct TCP_Segment            *seg;
    struct TCP_Segment           **next;

    if (length > tcb->mss) {
        length_more = length - tcb->mss;
        length      = tcb->mss;
    }

    /* Go to the end of the segment list */
    for (next = &tcb->segments; *next; next = &(*next)->next) {
        seqno = (unsigned)((*next)->seqno + (*next)->length);
    }

    /* Append this segment to the list */
    seg   = CALLOC(1, sizeof(*seg));
    *next = seg;

    seg->seqno  = seqno;
    seg->length = length;
    seg->is_dynamic  = is_dynamic;
    seg->buf = (unsigned char *)buf;

    if (tcb->tcpstate != STATE_ESTABLISHED_SEND)
        application_notify(tcpcon, tcb, APP_WHAT_SENDING, seg->buf, seg->length, 0, 0);


    /* If this is the head of the segment list, then transmit right away */
    if (tcb->segments == seg) {
        tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_PSH | TCP_FLAG_ACK,
            seg->buf, seg->length);
        _tcb_change_state_to(tcb, STATE_ESTABLISHED_SEND);
    }

    /* If the input buffer was too large to fit a single segment, then
     * split it up into multiple segments */
    if (length_more) {
        void *buf_more = MALLOC(length_more);
        memcpy(buf_more, (unsigned char *)buf+length, length_more);
        _tcb_seg_send(tcpcon, tcb, buf_more, length_more, 1);
    }
}

/***************************************************************************
 ***************************************************************************/
static int
_tcp_seg_acknowledge(
    struct TCP_Control_Block *tcb,
    uint32_t ackno)
{
    /* Normal: just discard repeats */
    if (ackno == tcb->seqno_me) {
        return 0;
    }

    /* Make sure this isn't a duplicate ACK from past
     * WRAPPING of 32-bit arithmetic happens here */
    if (ackno - tcb->seqno_me > 100000) {
        ipaddress_formatted_t fmt = ipaddress_fmt(tcb->ip_them);
        LOG(LEVEL_DETAIL,  "%s - "
                "tcb: ackno from past: "
                "old ackno = 0x%08x, this ackno = 0x%08x\n",
                fmt.string,
                tcb->ackno_me, ackno);
        return 0;
    }

    /* Make sure this isn't invalid ACK from the future
     * WRAPPING of 32-bit arithmetic happens here */
    if (tcb->seqno_me - ackno < 100000) {
        ipaddress_formatted_t fmt = ipaddress_fmt(tcb->ip_them);
        LOG(LEVEL_ERROR, "%s - "
                "tcb: ackno from future: "
                "my seqno = 0x%08x, their ackno = 0x%08x\n",
                fmt.string,
                tcb->seqno_me, ackno);
        return 0;
    }

    /*
    !Retire outstanding segments
    */
    {
        unsigned length = ackno - tcb->seqno_me;
        while (tcb->segments && length >= tcb->segments->length) {
            struct TCP_Segment *seg = tcb->segments;
            assert(seg->buf);

            tcb->segments    = seg->next;
            tcb->seqno_me   += seg->length;
            length          -= seg->length;
            
            LOGtcb(tcb, 1, "ACKed %u-bytes\n", seg->length);

            /* free the old segment */
            if (seg->is_dynamic) {
                free(seg->buf);
                seg->buf = NULL;
            }
            free(seg);
            if (ackno == tcb->ackno_them)
                return 1; /* good ACK */
        }

        if (tcb->segments && length < tcb->segments->length) {
            struct TCP_Segment *seg = tcb->segments;
            assert(seg->buf);

            tcb->seqno_me   += length;
            LOGtcb(tcb, 1, "ACKed %u-bytes\n", length);

            /* This segment needs to be reduced */
            if (seg->is_dynamic) {
                size_t new_length  = seg->length - length;
                unsigned char *buf = MALLOC(new_length);

                memcpy(buf, seg->buf + length, new_length);
                free(seg->buf);

                seg->buf        = buf;
                seg->length     = new_length;
                seg->is_dynamic = 1;

            } else {
                seg->buf += length;
            }
        }
    }
    
    /* Mark that this was a good ack */
    return 1;
}

/***************************************************************************
 ***************************************************************************/
int
tcpapi_set_timeout(struct stack_handle_t *socket, unsigned secs, unsigned usecs) {
    struct TCP_ConnectionTable *tcpcon = socket->tcpcon;
    struct TCP_Control_Block *tcb = socket->tcb;

    if (socket == NULL)
        return SOCKERR_EBADF;

    timeouts_add(tcpcon->timeouts, tcb->timeout,
             offsetof(struct TCP_Control_Block, timeout),
             TICKS_FROM_TV(socket->secs+secs, socket->usecs + usecs));
    return 0;
}


/***************************************************************************
 ***************************************************************************/
int
tcpapi_recv(struct stack_handle_t *socket) {
    struct TCP_Control_Block *tcb;

    if (socket == 0 || socket->tcb == 0)
        return SOCKERR_EBADF;
    tcb = socket->tcb;

    switch (tcb->tcpstate) {
        default:
        case STATE_ESTABLISHED_SEND:
            _tcb_change_state_to(socket->tcb, STATE_ESTABLISHED_RECV);
            break;
    }
    return 0;
}

int
tcpapi_send_data(struct stack_handle_t *socket,
            const void *buf, size_t length,
            unsigned is_dynamic) {

    /*no data*/
    if (!buf || !length) return 1;

    struct TCP_Control_Block *tcb;

    if (socket == 0 || socket->tcb == 0)
        return SOCKERR_EBADF;

    tcb = socket->tcb;
    switch (tcb->tcpstate) {
        case STATE_ESTABLISHED_RECV:
            _tcb_change_state_to(tcb, STATE_ESTABLISHED_SEND);
            /*follow through*/
        case STATE_ESTABLISHED_SEND:
            _tcb_seg_send(socket->tcpcon, tcb, buf, length, is_dynamic);
            return 0;
        default:
            LOG(LEVEL_WARNING, "TCP app attempted SEND in wrong state\n");
            return 1;
    }
}

unsigned
tcpapi_change_app_state(struct stack_handle_t *socket, enum App_State new_app_state) {
    struct TCP_Control_Block *tcb;

    if (socket == 0 || socket->tcb == 0)
        return SOCKERR_EBADF;

    tcb = socket->tcb;

    tcb->app_state = new_app_state;
    return new_app_state;
}


int
tcpapi_close(struct stack_handle_t *socket) {
    if (socket == NULL || socket->tcb == NULL)
        return SOCKERR_EBADF;
    tcpcon_send_packet(socket->tcpcon, socket->tcb, TCP_FLAG_RST, 0, 0);
    tcpcon_destroy_tcb(socket->tcpcon, socket->tcb, Reason_Shutdown);
    return 0;
}


/***************************************************************************
 ***************************************************************************/

static void
LOGSEND(struct TCP_Control_Block *tcb, const char *what)
{
    if (tcb == NULL)
        return;
    LOGip(5, tcb->ip_them, tcb->port_them, "=%s : --->> %s                  \n",
          tcp_state_to_string(tcb->tcpstate),
          what);
}

static int
_tcb_seg_recv(struct TCP_ConnectionTable *tcpcon,
    struct TCP_Control_Block *tcb,
    const unsigned char *payload, size_t payload_length,
    unsigned seqno_them,
    unsigned secs, unsigned usecs)
{
    if ((tcb->seqno_them - seqno_them) > payload_length)  {
        LOGSEND(tcb, "peer(ACK) [acknowledge payload 1]");
        tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_ACK, 0, 0);
        return 1;
    }

    while (seqno_them != tcb->seqno_them && payload_length) {
        seqno_them++;
        payload_length--;
        payload++;
    }

    if (payload_length == 0) {
        tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_ACK, 0, 0);
        return 1;
    }

    LOGtcb(tcb, 2, "received %u bytes\n", payload_length);

    tcb->seqno_them += payload_length;

    application_notify(tcpcon, tcb, APP_WHAT_RECV_PAYLOAD,
                       payload, payload_length, secs, usecs);

    /* Send ack for the data */
    tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_ACK, 0, 0);

    return 0;
}

/*****************************************************************************
 * Handles incoming events, like timeouts and packets, that cause a change
 * in the TCP control block "state".
 *****************************************************************************/
enum TCB_result
stack_incoming_tcp(struct TCP_ConnectionTable *tcpcon,
              struct TCP_Control_Block *tcb, enum TCP_What what,
              const unsigned char *payload, size_t payload_length,
              unsigned secs, unsigned usecs,
              unsigned seqno_them, unsigned ackno_them)
{

    /* FILTER
     * Reject out-of-order payloads
     * NOTE: payload and ACK are handled seperately
     */
    if (payload_length) {
        int payload_offset = seqno_them - tcb->seqno_them;
        if (payload_offset < 0) {
            /* This is a retransmission that we've already acknowledged */
            if (payload_offset <= 0 - (int)payload_length) {
                /* Both begin and end are old, so simply discard it */
                return TCB__okay;
            } else {
                /* Otherwise shorten the payload */
                payload_length += payload_offset;
                payload        -= payload_offset;
                seqno_them     -= payload_offset;
                assert(payload_length < 2000);
            }
        } else if (payload_offset > 0) {
            /* This is an out-of-order fragment in the future. an important design
             * of this light-weight stack is that we don't support this, and
             * force the other side to retransmit such packets */
            return TCB__okay;
        }
    }
    
    /* FILTER:
     * Reject out-of-order FINs.
     * Handle duplicate FINs here
     */
    if (what == TCP_WHAT_FIN) {
        if (seqno_them == tcb->seqno_them - 1) {
            /* Duplicate FIN(retransmission), respond with RST to close*/
            tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_RST, 0, 0);
            tcpcon_destroy_tcb(tcpcon, tcb, Reason_Shutdown);
            return TCB__destroyed;
        } else if (seqno_them != tcb->seqno_them) {
            /* out of order FIN, so drop it */
            LOGtcb(tcb, 1, "out-of-order FIN\n");
            return TCB__okay;
        }
    }

    LOGtcb(tcb, 1, "##%s##\n", what_to_string(what));

    /* Make sure no connection lasts longer than specified seconds */
    if (what == TCP_WHAT_TIMEOUT) {
        if (tcb->when_created + tcpcon->timeout_conn < secs) {
            LOGip(LEVEL_DETAIL, tcb->ip_them, tcb->port_them,
                "%s                \n",
                "CONNECTION TIMEOUT---");
            LOGSEND(tcb, "peer(RST)");
            tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_RST, 0, 0);
            tcpcon_destroy_tcb(tcpcon, tcb, Reason_Timeout);
            return TCB__destroyed;
        }
    }

    /*passive closed by target host's RST*/
    if (what == TCP_WHAT_RST) {
        LOGSEND(tcb, "tcb(destroy)");
        tcpcon_destroy_tcb(tcpcon, tcb, Reason_RST);
        return TCB__destroyed;
    }


    switch (tcb->tcpstate) {

        case STATE_SYN_SENT: {
            switch (what) {
                case TCP_WHAT_TIMEOUT:
                    tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_SYN, NULL, 0);
                    tcb->syns_sent++;
                    break;
                case TCP_WHAT_SYNACK:
                    tcb->seqno_them       = seqno_them;
                    tcb->seqno_them_first = seqno_them - 1;
                    tcb->seqno_me         = ackno_them;
                    tcb->seqno_me_first   = ackno_them - 1;

                    LOGtcb(tcb, 1, "%s connection established\n",
                        what_to_string(what));

                    tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_ACK, 0, 0);
                    _tcb_change_state_to(tcb, STATE_ESTABLISHED_RECV);

                    application_notify(tcpcon, tcb, APP_WHAT_CONNECTED, 0, 0, secs, usecs);
                    break;
                default:
                    ERRMSGip(tcb->ip_them, tcb->port_them, "%s:%s **** UNHANDLED EVENT ****\n", 
                        tcp_state_to_string(tcb->tcpstate), what_to_string(what));

                    break;
            }
            break;
        }

        case STATE_ESTABLISHED_SEND: {
            switch (what) {
                case TCP_WHAT_CLOSE:
                    tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_RST, 0, 0);
                    tcpcon_destroy_tcb(tcpcon, tcb, Reason_Shutdown);
                    return TCB__destroyed;
                    break;
                case TCP_WHAT_FIN:
                    if (seqno_them == tcb->seqno_them) {
                        /* I have ACKed all their data, so therefore process this */
                        tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_RST, 0, 0);
                        tcpcon_destroy_tcb(tcpcon, tcb, Reason_Shutdown);
                        return TCB__destroyed;
                    } else {
                        /* I haven't received all their data, so ignore it until I do */
                        tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_ACK, 0, 0);
                    }
                    break;
                case TCP_WHAT_ACK:
                    _tcp_seg_acknowledge(tcb, ackno_them);

                    if (tcb->segments == NULL || tcb->segments->length == 0) {
                        /* We've finished sending everything */
                        _tcb_change_state_to(tcb, STATE_ESTABLISHED_RECV);

                        /* All the payload has been sent. Notify the application of this, so that they
                         * can send more if the want, or switch to listening. */
                        application_notify(tcpcon, tcb, APP_WHAT_SEND_SENT, 0, 0, secs, usecs);

                    }
                    break;
                case TCP_WHAT_TIMEOUT:
                    _tcb_seg_resend(tcpcon, tcb);
                    break;
                case TCP_WHAT_DATA:
                    /* We don't receive data while in the sending state. We force them
                     * to keep re-sending it until we are prepared to receive it. This
                     * saves us from having to buffer it in this stack. */
                    break;
                case TCP_WHAT_SYNACK:
                    /** A delayed SYN-ACK.
                     * It can be solved by our pkt sending if it's a retransmission for lost ACK.
                    */
                    break;
                default:
                    ERRMSGip(tcb->ip_them, tcb->port_them, "%s:%s **** UNHANDLED EVENT ****\n", 
                        tcp_state_to_string(tcb->tcpstate), what_to_string(what));
                    break;
            }
            break;
        }

        case STATE_ESTABLISHED_RECV: {
            switch (what) {
                case TCP_WHAT_CLOSE:
                    tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_RST, 0, 0);
                    tcpcon_destroy_tcb(tcpcon, tcb, Reason_Shutdown);
                    return TCB__destroyed;
                    break;
                case TCP_WHAT_FIN:
                    if (seqno_them == tcb->seqno_them) {
                        /* I have ACKed all their data, so therefore process this */
                        tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_RST, 0, 0);
                        tcpcon_destroy_tcb(tcpcon, tcb, Reason_Shutdown);
                        return TCB__destroyed;
                    } else {
                        /* I haven't received all their data, so ignore it until I do */
                        tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_ACK, 0, 0);
                    }
                    break;
                case TCP_WHAT_ACK:
                    _tcp_seg_acknowledge(tcb, ackno_them);
                    break;
                case TCP_WHAT_TIMEOUT:
                    application_notify(tcpcon, tcb, APP_WHAT_RECV_TIMEOUT, 0, 0, secs, usecs);
                    break;
                case TCP_WHAT_DATA:
                    _tcb_seg_recv(tcpcon, tcb, payload, payload_length, seqno_them, secs, usecs);
                    break;
                case TCP_WHAT_SYNACK:
                    /** A delayed SYN-ACK.
                     * Maybe a retransmission for lost ACK?
                     * But our stack can't identify it, just give up.
                    */
                    break;
                default:
                    ERRMSGip(tcb->ip_them, tcb->port_them, "%s:%s **** UNHANDLED EVENT ****\n", 
                        tcp_state_to_string(tcb->tcpstate), what_to_string(what));
                    break;
            }
            break;
        }

        default: {
            ERRMSGip(tcb->ip_them, tcb->port_them, "%s:%s **** UNHANDLED EVENT ****\n", 
                tcp_state_to_string(tcb->tcpstate), what_to_string(what));
            break;
        }
    }

    return TCB__okay;
}

static const char *app_state_to_string(unsigned state) {
    switch (state) {
    case APP_STATE_INIT:          return "connect";
    case APP_STATE_RECV_HELLO:    return "wait-for-hello";
    case APP_STATE_RECV_NEXT:     return "receive";
    case APP_STATE_SEND_FIRST:    return "send-first";
    case APP_STATE_SEND_NEXT:     return "send";
    default: return "unknown";
    }
}
static const char *event_to_string(enum App_Event ev) {
    switch (ev) {
    case APP_WHAT_CONNECTED:      return "connected";
    case APP_WHAT_RECV_TIMEOUT:   return "timeout";
    case APP_WHAT_RECV_PAYLOAD:   return "payload";
    case APP_WHAT_SEND_SENT:      return "sent";
    case APP_WHAT_SENDING:        return "sending";
    default: return "unknown";
    }
}
 
void
application_event(struct stack_handle_t *socket,
    enum App_State state, enum App_Event event,
    const struct ProbeModule *probe,
    const void *payload, size_t payload_length) {

again:
    switch (state) {
        case APP_STATE_INIT: {
            switch (event) {
                case APP_WHAT_CONNECTED:
                    if (probe->hello_wait <= 0) {
                        tcpapi_change_app_state(socket, APP_STATE_SEND_FIRST);
                        state = APP_STATE_SEND_FIRST;
                        goto again;
                    } else {
                        tcpapi_set_timeout(socket, probe->hello_wait, 0);
                        tcpapi_recv(socket);
                        tcpapi_change_app_state(socket, APP_STATE_RECV_HELLO);
                    }
                    break;
                default:
                    ERRMSG("TCP.app: unhandled event: state=%s event=%s\n",
                        app_state_to_string(state), event_to_string(event));
                    break;
            }
            break;
        }

        case APP_STATE_RECV_HELLO: {
            switch (event) {
                case APP_WHAT_RECV_TIMEOUT:
                    /* We've got no response from the initial connection,
                     * so switch from them being responsible for communications
                     * to us being responsible, and start sending */
                    tcpapi_change_app_state(socket, APP_STATE_SEND_FIRST);
                    state = APP_STATE_SEND_FIRST;
                    goto again;
                    break;
                case APP_WHAT_RECV_PAYLOAD:
                    /* We've receive some data from them, so wait for some more.
                     * This means we won't be transmitting anything to them. */
                    tcpapi_change_app_state(socket, APP_STATE_RECV_NEXT);
                    state = APP_STATE_RECV_NEXT;
                    goto again;
                default:
                    ERRMSG("TCP.app: unhandled event: state=%s event=%s\n",
                        app_state_to_string(state), event_to_string(event));
                    break;
            }
            break;
        }

        case APP_STATE_RECV_NEXT: {
            switch (event) {
                case APP_WHAT_RECV_PAYLOAD: {

                    struct ProbeTarget target = {
                        .ip_them   = socket->tcb->ip_them,
                        .ip_me     = socket->tcb->ip_me,
                        .port_them = socket->tcb->port_them,
                        .port_me   = socket->tcb->port_me,
                        .cookie    = 0, /*state mode does not need cookie*/
                        .index     = socket->tcb->port_me-socket->tcpcon->src_port_start,
                    };

                    struct DataPass pass = {0};

                    unsigned is_multi =
                        probe->parse_response_cb(&pass, &socket->tcb->probe_state,
                            socket->tcpcon->out, &target,
                            (const unsigned char *)payload, payload_length);

                    /**
                     * Split the semantic of DataPass into Sending Data & Closing.
                     * Because our TCP API just handle one of each at a time.
                     * */
                    if (pass.len)
                        tcpapi_send_data(socket, pass.payload, pass.len, pass.is_dynamic);
                    if (pass.is_close)
                        tcpapi_close(socket);
                    
                    /**
                     * multi-probe Multi_AfterHandle.
                     * we use ip info from target because tcb maybe destroyed now
                     * */
                    if (probe->multi_mode==Multi_AfterHandle && is_multi
                        && target.port_me==socket->tcpcon->src_port_start) {
                        for (unsigned idx=1; idx<probe->multi_num; idx++) {

                            unsigned cookie = get_cookie(target.ip_them,
                                target.port_them,
                                target.ip_me,
                                socket->tcpcon->src_port_start+idx,
                                socket->tcpcon->entropy);
                            
                            tcpcon_send_raw_SYN(socket->tcpcon, target.ip_them,
                                target.port_them,
                                target.ip_me,
                                socket->tcpcon->src_port_start+idx,
                                cookie);
                        }
                    }

                    /**
                     * multi-probe Multi_DynamicNext
                     * we use ip info from target because tcb maybe destroyed now
                     * */
                    if (probe->multi_mode==Multi_DynamicNext && is_multi) {

                        unsigned cookie = get_cookie(target.ip_them,
                            target.port_them,
                            target.ip_me,
                            socket->tcpcon->src_port_start+is_multi-1,
                            socket->tcpcon->entropy);

                        tcpcon_send_raw_SYN(socket->tcpcon, target.ip_them,
                            target.port_them,
                            target.ip_me,
                            socket->tcpcon->src_port_start+is_multi-1,
                            cookie);
                    }

                    break;
                }
                case APP_WHAT_RECV_TIMEOUT:
                    break;
                case APP_WHAT_SENDING:
                    /* A higher level protocol has started sending packets while processing
                     * a receive, therefore, change to the SEND state */
                    tcpapi_change_app_state(socket, APP_STATE_SEND_NEXT);
                    break;
                case APP_WHAT_SEND_SENT:
                    /* FIXME */
                    break;
                default:
                    ERRMSG("TCP.app: unhandled event: state=%s event=%s\n",
                        app_state_to_string(state), event_to_string(event));
                    break;
            }
            break;
        }

        case APP_STATE_SEND_FIRST: {

            struct ProbeTarget target = {
                .ip_them   = socket->tcb->ip_them,
                .port_them = socket->tcb->port_them,
                .ip_me     = socket->tcb->ip_me,
                .port_me   = socket->tcb->port_me,
                .cookie    = 0,          /*does not support cookie now*/
                .index     = socket->tcb->port_me-socket->tcpcon->src_port_start,
            };

            struct DataPass pass = {0};

            probe->make_hello_cb(&pass, &socket->tcb->probe_state, &target);
            
            /**
             * Split the semantic of DataPass into Sending Data & Closing.
             * Because our TCP API just handle one of each at a time.
             * */
            if (pass.len)
                tcpapi_send_data(socket, pass.payload, pass.len, pass.is_dynamic);
            if (pass.is_close)
                tcpapi_close(socket);

            tcpapi_change_app_state(socket, APP_STATE_SEND_NEXT);
            break;
        }

        case APP_STATE_SEND_NEXT: {
            switch (event) {
                case APP_WHAT_SEND_SENT:
                    /* We've got an acknowledgement that all our data
                     * was sent. Therefore, change the receive state */
                    tcpapi_recv(socket);
                    tcpapi_change_app_state(socket, APP_STATE_RECV_NEXT);
                    break;
                case APP_WHAT_SENDING:
                    break;
                default:
                    ERRMSG("TCP.app: unhandled event: state=%s event=%s\n",
                        app_state_to_string(state), event_to_string(event));
                    break;
            }
            break;
        }

        default: {
            ERRMSG("TCP.app: unhandled event: state=%s event=%s\n",
                app_state_to_string(state), event_to_string(event));
            break;
        }
    }
}
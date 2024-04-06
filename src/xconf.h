#ifndef XCONF_H
#define XCONF_H

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "util-data/safe-string.h"
#include "util-misc/cross.h"
#include "timeout/fast-timeout.h"
#include "massip/massip-addr.h"
#include "massip/massip.h"
#include "massip/massip.h"
#include "stack/stack-src.h"
#include "stack/stack-queue.h"
#include "output-modules/output-modules.h"
#include "probe-modules/probe-modules.h"
#include "scan-modules/scan-modules.h"


struct Adapter;
struct TemplateSet;
struct TemplateOptions;

enum Operation {
    Operation_Default              =  0,     /* nothing specified, so print usage */
    Operation_ListAdapters         =  1,     /* list all usable interfaces */
    Operation_Scan                 =  3,     /* do scan */
    Operation_ListTargets          =  5,     /* list all targets uniquely in random */
    Operation_ListRange            =  7,     /* list all targets in range */
    Operation_Echo                 =  9,     /* echo the config used now or all configs with --echo-all */
    Operation_ListCidr             = 11,     /* list all targets in CIDR */
    Operation_ListScanModules,               /* list all scan modules */
    Operation_ListProbeModules,              /* list all probes */
    Operation_ListOutputModules,             /* list all probes */
    Operation_PrintHelp,                     /* print help text for all parameters*/
};

struct source_t {
    unsigned         ipv4;
    unsigned         ipv4_mask;
    unsigned         port;
    unsigned         port_mask;
    ipv6address      ipv6;
    ipv6address      ipv6_mask;
};


/**
 * Once read in at the start, this structure doesn't change unless we know what
 * is happenning.
 * The transmit and receive threads have only a "const" pointer to this structure.
 */
struct Xconf
{
    /**
     * Just one network adapters that we'll use for scanning. Adapter
     * should have a set of IP source addresses, except in the case
     * of PF_RING dnaX:Y adapters.
     */
    struct {
        char                     ifname[256];
        struct Adapter          *adapter;
        struct stack_src_t       src;
        macaddress_t             source_mac;
        macaddress_t             router_mac_ipv4;
        macaddress_t             router_mac_ipv6;
        ipv4address_t            router_ip;
        int                      link_type;       /* libpcap definitions */
        unsigned char            my_mac_count;    /*is there a MAC address? */
        unsigned                 vlan_id;
        unsigned                 is_vlan:1;
        unsigned                 is_usable:1;
    } nic;

    struct {
        /** --resume-index */
        uint64_t index;
        /** --resume-count */
        uint64_t count;
        /** Derives the --resume-index from the target ip:port */
        struct {
            unsigned ip;
            unsigned port;
        } target;
    } resume;

    struct {
        unsigned one;
        unsigned of;
    } shard;
    
    /**
     * Temporary file to echo parameters to, used for saving configuration
     * to a file
     */
    FILE      *echo;
    unsigned   echo_all;

    /**
     * This stack contains:
     *     The callback queue (transmit queue) from rx threads to tx threads,
     *     The packet buffer queue for memory reusing.
     * 
    */
    struct stack_t *stack;
    unsigned stack_buf_count;

    /**
     * set pcap BPF filter and save pcap file
    */
    char *bpf_filter;
    char  pcap_filename[256];

    /**
     * template for packet making quickly.
    */
    struct TemplateSet       *tmplset;
    struct TemplateOptions   *templ_opts; /* e.g. --tcpmss */

    /**
     * Use fast-timeout table to handle simple timeout events;
    */
    struct FTable    *ft_table;
    time_t            ft_spec;          /*timeout seconds*/

    struct MassIP targets;
    struct MassIP exclude;

    struct ProbeModule *probe_module;
    char *probe_module_args;

    struct ScanModule *scan_module;
    char *scan_module_args;

    /**
     * We could set the number of transmit threads.
     * NOTE: Always only one receiving thread for consistency of dedup, timeout....
     * But, we have recv-handlers in multi threads to exec handle_cb of ScanModule.
     * Now we could set the number of recv-handlers in the power of 2.
     */
    unsigned tx_thread_count;
    unsigned rx_handler_count;

    struct Output     output;                /*results outputing*/
    enum Operation    op;                    /*operation of proc*/
    uint64_t          seed;
    double            max_rate;
    unsigned          wait;                  /*default 10 seconds*/
    unsigned          dedup_win;             /*windows size of dedup table*/
    unsigned          blackrock_rounds;
    unsigned          dispatch_buf_count;    /* dispacth queue size in recv*/
    uint64_t          tcb_count;             /*tcb count for tcp state scan*/
    unsigned          tcp_init_window;       /*window of the first syn or syn-ack packet*/
    unsigned          tcp_window;            /*window of other packets*/
    unsigned          packet_ttl;            /* starting IP TTL field */
    unsigned          packet_trace:1;        /* --packet-trace */
    unsigned          is_status_ndjson:1;    /* --status-ndjson*/
    unsigned          is_status_queue:1;     /* --print-status queue*/
    unsigned          is_status_info_num:1;  /* --print-status info-num*/
    unsigned          is_pfring:1;           /* --pfring */
    unsigned          is_sendq:1;            /* --sendq */
    unsigned          is_offline:1;          /* --offline */
    unsigned          is_nodedup:1;          /* --nodedup, don't deduplicate */
    unsigned          is_gmt:1;              /* --gmt, all times in GMT */
    unsigned          is_infinite:1;         /* --infinite */
    unsigned          is_fast_timeout:1;     /* --fast-timeout, use ft for ScanModule*/

};


void xconf_command_line(struct Xconf *xconf, int argc, char *argv[]);
void xconf_save_state(struct Xconf *xconf);

/**
 * Pre-scan the command-line looking for options that may affect how
 * previous options are handled. This is a bit of a kludge, really.
 */
bool xconf_contains(const char *x, int argc, char **argv);

/**
 * Called to set a <name=value> pair.
 */
void
xconf_set_parameter(struct Xconf *xconf,
                      const char *name, const char *value);

/**
 * Echoes the settings to the command-line. By default, echoes only
 * non-default values. With "echo-all", everything is echoed.
 */
void
xconf_echo(struct Xconf *xconf, FILE *fp);

/**
 * Echoes the list of CIDR ranges to scan.
 */
void
xconf_echo_cidr(struct Xconf *xconf, FILE *fp);


/***************************************************************************
 * We support a range of source IP/port. This function converts that
 * range into useful variables we can use to pick things form that range.
 ***************************************************************************/
void
adapter_get_source_addresses(const struct Xconf *xconf, struct source_t *src);

void xconf_print_usage();

void xconf_print_help();

#endif

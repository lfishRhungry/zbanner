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

/**
 * some default config
*/
/* 14 rounds seem to give way better statistical distribution than 4 with a
very low impact on scan rate */
#define XCONF_DFT_BLACKROCK_ROUND                  14
#define XCONF_DFT_TX_THD_COUNT                      4
#define XCONF_DFT_RX_HDL_COUNT                      1
#define XCONF_DFT_STACK_BUF_COUNT               16384
#define XCONF_DFT_DISPATCH_BUF_COUNT            16384
#define XCONF_DFT_MAX_RATE                      100.0
#define XCONF_DFT_DEDUP_WIN                   1000000
#define XCONF_DFT_FT_SPEC                           5
#define XCONF_DFT_SHARD_ONE                         1
#define XCONF_DFT_SHARD_OF                          1
#define XCONF_DFT_WAIT                             10
#define XCONF_DFT_PORT_RANGE                      256
#define XCONF_DFT_SNAPLEN                       65535  /*also the max*/
#define XCONF_DFT_MAX_PKT_LEN                    1514


struct Adapter;
struct TemplateSet;
struct TemplateOptions;

enum Operation {
    Operation_Default = 0,                   /* nothing specified, so print usage */
    Operation_Scan,                          /* do scan */
    Operation_Echo,                          /* echo the config used now or all configs with --echo-all */
    Operation_DebugIF,                       /* do special selftest to interface for debugging*/
    Operation_ListCidr,                      /* list all target IPs in CIDR */
    Operation_ListRange,                     /* list all target IPs in range */
    Operation_ListTargets,                   /* list all target IPs uniquely in random */
    Operation_ListAdapters,                  /* list all usable interfaces */
    Operation_ListScanModules,               /* list all scan modules */
    Operation_HelpScanModule,                /* print help of specified scan module */
    Operation_ListProbeModules,              /* list all probes */
    Operation_HelpProbeModule,               /* print help of specified probe module */
    Operation_ListOutputModules,             /* list all probes */
    Operation_HelpOutputModule,              /* print help of specified output module */
    Operation_PrintHelp,                     /* print help text for all parameters*/
    Operation_PrintIntro,                    /* print introduction text of work flow*/
    Operation_PrintVersion,                  /* print version and build info*/
    Operation_Selftest,                      /* do global regression test*/
    Operation_Benchmark,                     /* do global benchmark for key units */
};

struct source_t {
    unsigned         ipv4;
    unsigned         ipv4_mask;
    unsigned         port;
    unsigned         port_mask;
    ipv6address      ipv6;
    uint64_t         ipv6_mask;
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
        unsigned                 vlan_id;
        unsigned                 snaplen;
        int                      link_type;
        unsigned char            my_mac_count;    /*is there a MAC address? */
        unsigned                 is_vlan:1;
        unsigned                 is_usable:1;
    } nic;

    struct {
        uint64_t index;
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

    struct stack_t *stack;
    unsigned stack_buf_count;

    char     *bpf_filter;
    char      pcap_filename[256];

    /**
     * template for packet making quickly.
    */
    struct TemplateSet       *tmplset;
    struct TemplateOptions   *templ_opts;

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
     * NOTE: Always only one receiving thread for consistency of dedup, timeout
     * and packets recording....
     * But, we have recv-handlers in multi threads to exec handle_cb of ScanModule.
     * Now we could set the number of recv-handlers in the power of 2.
     */
    unsigned tx_thread_count;
    unsigned rx_handler_count;

    OutConf           out;
    enum Operation    op;
    uint64_t          seed;
    uint64_t          repeat;
    double            max_rate;
    unsigned          wait;
    unsigned          dedup_win;
    unsigned          blackrock_rounds;
    unsigned          dispatch_buf_count;
    uint64_t          tcb_count;
    unsigned          tcp_init_window;
    unsigned          tcp_window;
    unsigned          packet_ttl;
    unsigned          max_packet_len;
    unsigned          packet_trace:1;
    unsigned          is_status_ndjson:1;
    unsigned          is_status_queue:1;
    unsigned          is_status_info_num:1;
    unsigned          is_status_hit_rate:1;
    unsigned          is_pfring:1;
    unsigned          is_sendq:1;
    unsigned          is_offline:1;
    unsigned          is_nodedup:1;
    unsigned          is_noresume:1;
    unsigned          is_infinite:1;
    unsigned          is_fast_timeout:1;
    unsigned          is_bypass_os:1;
    unsigned          is_no_bpf:1;
    unsigned          is_no_cpu_bind:1;
    unsigned          is_static_seed:1;

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
void xconf_set_parameter(struct Xconf *xconf,
    const char *name, const char *value);

/**
 * Echoes the settings to the command-line. By default, echoes only
 * non-default values. With "echo-all", everything is echoed.
 */
void xconf_echo(struct Xconf *xconf, FILE *fp);

/**
 * Echoes the list of CIDR ranges to scan.
 */
void xconf_echo_cidr(struct Xconf *xconf, FILE *fp);

void xconf_print_intro();

void xconf_print_usage();

void xconf_print_help();

void xconf_print_version();

void xconf_selftest();

void xconf_benchmark(unsigned blackrock_rounds);

#endif

#ifndef XCONF_H
#define XCONF_H

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "util/mas-safefunc.h"
#include "util/bool.h"
#include "massip/massip-addr.h"
#include "massip/massip.h"
#include "massip/massip.h"
#include "stack/stack-src.h"
#include "stack/stack-queue.h"
#include "stateless-probes/stateless-probes.h"
#include "scan-modules/scan_modules.h"


/**
 * Useful predefinition for xtate
*/
#define XTATE_NAME                "xtate"
#define XTATE_UPPER_NAME          "XTATE"
#define XTATE_FIRST_UPPER_NAME    "Xtate"
#define XTATE_VERSION             "1.0beta"
#define XTATE_WITH_VERSION        "xtate/1.0beta"
#define XTATE_DEFAULT_CONF        "/etc/xtate/xtate.conf"
#define XTATE_GITHUB              "https://github.com/lfishRhungry/xtate"
#define XTATE_GITHUB_ISSUES       "https://github.com/lfishRhungry/xtate/issues"


struct Adapter;
struct TemplateSet;
struct TemplateOptions;

/**
 * This is the "operation" to be performed by xconf, which is almost always
 * to "scan" the network. However, there are some lesser operations to do
 * instead, like run a "regression self test", or "debug", or something else
 * instead of scanning. We parse the command-line in order to figure out the
 * proper operation
 */
enum Operation {
    Operation_Default = 0,          /* nothing specified, so print usage */
    Operation_ListAdapters = 1,    /* --listif */
    Operation_Scan = 3,         /* this is what you expect */
    Operation_DebugIF = 4,          /* --debug if */
    Operation_ListTargets = 5,         /* -sL */
    Operation_ReadRange = 7,        /* --readrange */
    Operation_Echo = 9,             /* --echo */
    Operation_EchoCidr = 11,        /* --echo-cidr */
    Operation_ListProbes,          /* --list-probes*/
    Operation_ListScanModules,         /* --list-modules*/
};

struct source_t {
    unsigned ipv4;
    unsigned ipv4_mask;
    unsigned port;
    unsigned port_mask;
    ipv6address ipv6;
    ipv6address ipv6_mask;
};


/**
 * This is the master configuration structure. It is created on startup
 * by reading the command-line and parsing configuration files.
 *
 * Once read in at the start, this structure doesn't change. The transmit
 * and receive threads have only a "const" pointer to this structure.
 */
struct Xconf
{
    /**
     * What this program is doing, which is normally "Operation_Scan", but
     * which can be other things, like "Operation_SelfTest"
     */
    enum Operation op;
    
    struct {
        unsigned tcp:1;
        unsigned udp:1;     /* -sU */
        unsigned sctp:1;
        unsigned ping:1;    /* --ping, ICMP echo */
        unsigned arp:1;     /* --arp, local ARP scan */
        unsigned oproto:1;  /* -sO */
    } scan_type;
    
    /**
     * After scan type has been configured, add these ports. In other words,
     * the user may specify `-sU` or `-sT` after the `--top-ports` parameter,
     * so we have to wait until after parsing arguments to fill in the ports.
     */
    unsigned top_ports;
    
    /**
     * Temporary file to echo parameters to, used for saving configuration
     * to a file
     */
    FILE *echo;
    unsigned echo_all;

    /**
     * Just one network adapters that we'll use for scanning. Adapter
     * should have a set of IP source addresses, except in the case
     * of PF_RING dnaX:Y adapters.
     */
    struct {
        char ifname[256];
        struct Adapter *adapter;
        struct stack_src_t src;
        macaddress_t source_mac;
        macaddress_t router_mac_ipv4;
        macaddress_t router_mac_ipv6;
        ipv4address_t router_ip;
        int link_type; /* libpcap definitions */
        unsigned char my_mac_count; /*is there a MAC address? */
        unsigned vlan_id;
        unsigned is_vlan:1;
        unsigned is_usable:1;
    } nic;

    /**
     * Now we could set the number of transmit threads.
     * NOTE: Always only one receiving thread.
     * !Actually, more than one rx thread make deduptable invalid.
     * !And rx thread cost much less than tx thread, one rx could serve many tx well.
     * TODO: maybe some costy thing(eg. identification) could be done by other
     * thread instead of rx or tx.
     */
    unsigned tx_thread_count;
    /**
     * NOTE: Just keep this value for funcs in output.c
    */
    unsigned rx_thread_count;

    /* This is used by ScanModule both in transmit and receive thread for
     * formatting packets */
    // struct TemplatePacket *tmpl_pkt;
    struct TemplateSet *tmplset;

    /**
     * This is the number of entries in our table.
     * More entries does a better job at the cost of using more memory.
     * NOTE: Look into strustures to understand the memory cost.
     */
    unsigned dedup_win;

    /**
     * This stack contains:
     *     The callback queue (transmit queue) from rx threads to tx threads,
     *     The packet buffer queue for memory reusing.
     * 
    */
    struct stack_t *stack;
    unsigned stack_buf_count;

    /**
     * The target ranges of IPv4 addresses that are included in the scan.
     * The user can specify anything here, and we'll resolve all overlaps
     * and such, and sort the target ranges.
     */
    struct MassIP targets;
    
    /**
     * IPv4 addresses/ranges that are to be excluded from the scan. This takes
     * precedence over any 'include' statement. What happens is this: after
     * all the configuration has been read, we then apply the exclude/blacklist
     * on top of the target/whitelist, leaving only a target/whitelist left.
     * Thus, during the scan, we only choose from the target/whitelist and
     * don't consult the exclude/blacklist.
     */
    struct MassIP exclude;


    /**
     * Maximum rate, in packets-per-second (--rate parameter). This can be
     * a fraction of a packet-per-second, or be as high as 30000000.0 (or
     * more actually, but I've only tested to 30megapps).
     */
    double max_rate;

	/**
     * application probe/request for stateless mode
    */
    struct StatelessProbe *stateless_probe;
    char stateless_probe_args[STATELESS_PROBE_ARGS_LEN];

	/**
     * Choosed ScanModule
    */
    struct ScanModule *scan_module;
    char scan_module_args[SCAN_MODULE_ARGS_LEN];

    unsigned is_show_failed:1;
    unsigned is_status_ndjson:1;
    unsigned is_pfring:1;       /* --pfring */
    unsigned is_sendq:1;        /* --sendq */
    unsigned is_stateless_banners:1; /* --stateless, --stateless-banners, get banners in stateless mode*/
    unsigned is_offline:1;      /* --offline */
    unsigned is_nodedup:1;      /* --nodedup, don't deduplicate */
    unsigned is_gmt:1;          /* --gmt, all times in GMT */
    unsigned is_infinite:1;     /* -infinite */

    /**
     * Wait forever for responses, instead of the default 10 seconds
     */
    unsigned wait;

    /**
     * --resume
     * This structure contains options for pausing the scan (by exiting the
     * program) and restarting it later.
     */
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

    /**
     * --shard n/m
     * This is used for distributing a scan across multiple "shards". Every
     * shard in the scan must know the total number of shards, and must also
     * know which of those shards is it's identity. Thus, shard 1/5 scans
     * a different range than 2/5. These numbers start at 1, so it's
     * 1/3 (#1 out of three), 2/3, and 3/3 (but not 0/3).
     */
    struct {
        unsigned one;
        unsigned of;
    } shard;

    /**
     * A random seed for randomization if zero, otherwise we'll use
     * the configured seed for repeatable tests.
     */
    uint64_t seed;

    /**
     * The packet template set we are current using. We store a binary template
     * for TCP, UDP, SCTP, ICMP, and so on. All the scans using that protocol
     * are then scanned using that basic template. IP and TCP options can be
     * added to the basic template without affecting any other component
     * of the system.
     */
    struct TemplateSet *pkt_template;

    /** Packet template options, such as whether we should add a TCP MSS
     * value, or remove it from the packet */
    struct TemplateOptions *templ_opts; /* e.g. --tcpmss */
    
    struct {
        unsigned data_length; /* number of bytes to randomly append */
        unsigned ttl; /* starting IP TTL field */
        unsigned badsum; /* bad TCP/UDP/SCTP checksum */

        unsigned packet_trace:1; /* print transmit messages */
        
        char datadir[256];
    } nmap;

    char pcap_filename[256];

    struct {
        unsigned timeout;
    } tcb;

    struct {
        char *pcap_payloads_filename;
        char *nmap_payloads_filename;
        char *nmap_service_probes_filename;
    
        struct PayloadsUDP *udp;
        struct PayloadsUDP *oproto;
        struct NmapServiceProbeList *probes;
    } payloads;
    

    char *bpf_filter;

    /**
     * --min-packet
     */
    unsigned min_packet_size;

    /**
     * Number of rounds for randomization
     * --blackrock-rounds
     */
    unsigned blackrock_rounds;

};


void xconf_command_line(struct Xconf *xconf, int argc, char *argv[]);
void xconf_save_state(struct Xconf *xconf);

/**
 * Load databases, such as:
 *  - nmap-payloads
 *  - nmap-service-probes
 *  - pcap-payloads
 */
void load_database_files(struct Xconf *xconf);

/**
 * Pre-scan the command-line looking for options that may affect how
 * previous options are handled. This is a bit of a kludge, really.
 */
int xconf_contains(const char *x, int argc, char **argv);

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


#endif

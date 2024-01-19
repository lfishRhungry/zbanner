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
struct Banner1;
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
    Operation_List_Adapters = 1,    /* --listif */
    Operation_Selftest = 2,         /* --selftest or --regress */
    Operation_Scan = 3,         /* this is what you expect */
    Operation_DebugIF = 4,          /* --debug if */
    Operation_ListScan = 5,         /* -sL */
    Operation_ReadScan = 6,         /* --readscan <binary-output> */
    Operation_ReadRange = 7,        /* --readrange */
    Operation_Benchmark = 8,        /* --benchmark */
    Operation_Echo = 9,             /* --echo */
    Operation_EchoAll = 10,         /* --echo-all */
    Operation_EchoCidr = 11,        /* --echo-cidr */
    Operation_List_Probes,          /* --list-probes*/
};

/**
 * The format of the output. If nothing is specified, then the default will
 * be "--interactive", meaning that we'll print to the command-line live as
 * results come in. Only one output format can be specified, except that
 * "--interactive" can be specified alongside any of the other ones.
 */
enum OutputFormat {
    Output_Default      = 0x0000,
    Output_Interactive  = 0x0001,   /* --interactive, print to cmdline */
    Output_List         = 0x0002,
    Output_Binary       = 0x0004,   /* -oB, "binary", the primary format */
    Output_XML          = 0x0008,   /* -oX, "xml" */
    Output_JSON         = 0x0010,   /* -oJ, "json" */
    Output_NDJSON       = 0x0011,   /* -oD, "ndjson" */
    Output_Nmap         = 0x0020,
    Output_ScriptKiddie = 0x0040,
    Output_Grepable     = 0x0080,   /* -oG, "grepable" */
    Output_Redis        = 0x0100, 
    Output_Unicornscan  = 0x0200,   /* -oU, "unicornscan" */
    Output_None         = 0x0400,
    Output_Certs        = 0x0800,
    Output_Hostonly     = 0x1000,   /* -oH, "hostonly" */
    Output_All          = 0xFFBF,   /* not supported */
};


/**
 * Holds the list of TCP "hello" payloads, specified with the "--hello-file"
 * or "--hello-string" options
 */
struct TcpCfgPayloads
{
    /** The "hello" data in base64 format. This is either the base64 string
     * specified in the cmdline/cfgfile with "--hello-string", or the 
     * contents of a file specified with "--hello-file" that we've converted
     * into base64 */
    char *payload_base64;
    
    /** The TCP port that this hello belongs to */
    unsigned port;
    
    /** These configuration options are stored as a linked-list */
    struct TcpCfgPayloads *next;
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

    /* This is used both by the transmit and receive thread for
     * formatting packets */
    struct TemplateSet *tmplset;

    /**
     * This is the number of entries in our table.
     * More entries does a better job at the cost of using more memory.
     * NOTE: Look into strustures to understand the memory cost.
     */
    unsigned dedup_win1;
    unsigned dedup_win2;

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
     * Only output these types of banners
     */
    struct RangeList banner_types;


    /**
     * Maximum rate, in packets-per-second (--rate parameter). This can be
     * a fraction of a packet-per-second, or be as high as 30000000.0 (or
     * more actually, but I've only tested to 30megapps).
     */
    double max_rate;

    /**
     * Number of retries (--retries or --max-retries parameter). Retries
     * happen a few seconds apart.
     */
    unsigned retries;

	/**
     * application probe/request for stateless mode
    */
    struct StatelessProbe *stateless_probe;
    char stateless_probe_args[STATELESS_PROBE_ARGS_LEN];
    
    unsigned is_pfring:1;       /* --pfring */
    unsigned is_sendq:1;        /* --sendq */
    unsigned is_banners:1;      /* --banners */
    unsigned is_banners_rawudp:1; /* --rawudp */
    unsigned is_stateless_banners:1; /* --stateless, --stateless-banners, get banners in stateless mode*/
    unsigned is_offline:1;      /* --offline */
    unsigned is_noreset1:1;      /* --noreset1, don't transmit RST in PORT-IS-OPEN phase*/
    unsigned is_noreset2:1;      /* --noreset2, don't transmit RST in DATA-IS-RESPONED phase*/
    unsigned is_nodedup1:1;      /* --nodedup1, don't deduplicate for SYN-ACK */
    unsigned is_nodedup2:1;      /* --nodedup2, don't deduplicate Data Response */
    unsigned is_gmt:1;          /* --gmt, all times in GMT */
    unsigned is_capture_cert:1; /* --capture cert */
    unsigned is_capture_html:1; /* --capture html */
    unsigned is_capture_heartbleed:1; /* --capture heartbleed */
    unsigned is_capture_ticketbleed:1; /* --capture ticket */
    unsigned is_capture_stateless:1; /* --capture stateless */
    unsigned is_infinite:1;     /* -infinite */
    unsigned is_readscan:1;     /* --readscan, Operation_Readscan */
    unsigned is_heartbleed:1;   /* --heartbleed, scan for this vuln */
    unsigned is_ticketbleed:1;  /* --ticketbleed, scan for this vuln */
    unsigned is_poodle_sslv3:1; /* --vuln poodle, scan for this vuln */
    unsigned is_hello_ssl:1;    /* --ssl, use SSL HELLO on all ports */
    unsigned is_hello_smbv1:1;  /* --smbv1, use SMBv1 hello, instead of v1/v2 hello */
    unsigned is_hello_http:1;    /* --hello=http, use HTTP on all ports */
    unsigned is_scripting:1;    /* whether scripting is needed */
    unsigned is_capture_servername:1; /* --capture servername */

    /** Packet template options, such as whether we should add a TCP MSS
     * value, or remove it from the packet */
    struct TemplateOptions *templ_opts; /* e.g. --tcpmss */

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
     * The packet template set we are current using. We store a binary template
     * for TCP, UDP, SCTP, ICMP, and so on. All the scans using that protocol
     * are then scanned using that basic template. IP and TCP options can be
     * added to the basic template without affecting any other component
     * of the system.
     */
    struct TemplateSet *pkt_template;

    /**
     * A random seed for randomization if zero, otherwise we'll use
     * the configured seed for repeatable tests.
     */
    uint64_t seed;
    
    /**
     * This block configures what we do for the output files
     */
    struct OutputStuff {
        
        /**
         * --output-format
         * Examples are "xml", "binary", "json", "ndjson", "grepable", and so on.
         */
        enum OutputFormat format;
        
        /**
         * --output-filename
         * The name of the file where we are storing scan results.
         * Note: the filename "-" means that we should send the file to
         * <stdout> rather than to a file.
         */
        char filename[256];
        
        /**
         * A feature of the XML output where we can insert an optional 
         * stylesheet into the file for better rendering on web browsers
         */
        char stylesheet[256];

        /**
         * --append
         * We should append to the output file rather than overwriting it.
         */
        unsigned is_append:1;

        /**
         * --feedlzr
         * Output SYN-ACK info in format of feeding to LZR like:
         *     {"saddr":"42.194.129.165","daddr":"112.31.213.24","sport":80,"dport":49088,"seqnum":3867723978,"acknum":3830569963,"window":14600}
         * Use it for port scanning with `--noreset1` flag.
         * Do not use --show or --noshow.
        */
        unsigned is_feed_lzr:1;
        
        /**
         * --json-status
         * Print each status update line to stderr as JSON ending with a newline
         *
         * This only applies to the three types of status lines that are printed
         * in xtatus_print(); it does *not* apply to things like startup messages,
         * error messages or discovery of individual ports
         *
         */
        bool is_status_ndjson;

        /**
         * --open
         * --open-only
         * --show open
         * Whether to show open ports
         */
        unsigned is_show_open:1;
        
        /**
         * --show closed
         * Whether to show closed ports (i.e. RSTs)
         */
        unsigned is_show_closed:1;
        
        /**
         * --show host
         * Whether to show host messages other than closed ports
         */
        unsigned is_show_host:1;
        
        /**
         * print reason port is open, which is redundant for us 
         */
        unsigned is_reason:1;
    
        /**
         * --interactive
         * Print to command-line while also writing to output file. This isn't
         * needed if the output format is already 'interactive' (the default),
         * but only if the default output format is anything else, and the
         * user also wants interactivity.
         */
        unsigned is_interactive:1;
        
        /**
        * Print state updates
        */
        unsigned is_status_updates:1;

        struct {
            /**
             * When we should rotate output into the target directory
             */
            unsigned timeout;
            
            /**
             * When doing "--rotate daily", the rotation is done at GMT. In 
             * order to fix this, add an offset.
             */
            unsigned offset;
            
            /**
             * Instead of rotating by timeout, we can rotate by filesize 
             */
            uint64_t filesize;
            
            /**
             * The directory to which we store rotated files
             */
            char directory[256];
        } rotate;
    } output;

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
        struct TcpCfgPayloads *tcp;
        struct NmapServiceProbeList *probes;
    } payloads;
    
    /** Reconfigure the HTTP header */
    struct {
        /* Method */
        unsigned char *method;
        size_t method_length;

        /* URL */
        unsigned char *url;
        size_t url_length;

        /* Version */
        unsigned char *version;
        size_t version_length;

        /* Host */
        unsigned char *host;
        size_t host_length;

        /* User-Agent */
        unsigned char *user_agent;
        size_t user_agent_length;

        /* Payload after the header*/
        unsigned char *payload;
        size_t payload_length;

        /* Headers */
        struct {
            const char *name;
            unsigned char *value;
            size_t value_length;
        } headers[16];
        size_t headers_count;

        /* Cookies */
        struct {
            unsigned char *value;
            size_t value_length;
        } cookies[16];
        size_t cookies_count;

        /* Remove */
        struct {
            unsigned char *name;
        } remove[16];
        size_t remove_count;
    } http;

    unsigned tcp_connection_timeout;
    
    /** Number of seconds to wait for a 'hello' from the server before
     * giving up and sending a 'hello' from the client. Should be a small
     * value when doing scans that expect client-side hellos, like HTTP or
     * SSL, but should be a longer value when doing scans that expect server
     * hellos, such as FTP or VNC */
    unsigned tcp_hello_timeout;


    char *bpf_filter;

    struct {
        ipaddress ip;
        char      password[20];
        unsigned port;
    } redis;



    /**
     * --min-packet
     */
    unsigned min_packet_size;

    /**
     * Number of rounds for randomization
     * --blackrock-rounds
     */
    unsigned blackrock_rounds;
    
    /**
     * --script <name>
     */
    struct {
        /* The name (filename) of the script to run */
        char *name;
        
        /* The script VM */
        struct lua_State *L;
    } scripting;

    
    /**
     * --vuln <name>
     * The name of a vuln to check, like "poodle"
     */
    const char *vuln_name;

};


int xconf_selftest(void);
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
xconf_echo(struct Xconf *xconf, FILE *fp, unsigned is_echo_all);

/**
 * Echoes the list of CIDR ranges to scan.
 */
void
xconf_echo_cidr(struct Xconf *xconf, FILE *fp, unsigned is_echo_all);


#endif
/*
    Read in the configuration for XTATE.

    Configuration parameters can be read either from the command-line
    or a configuration file. Long parameters of the --xxxx variety have
    the same name in both.

    Most of the code in this module is for 'nmap' options we don't support.
    That's because we support some 'nmap' options, and I wanted to give
    more feedback for some of them why they don't work as expected, such
    as reminding people that this is an asynchronous scanner.

*/

#include <ctype.h>
#include <limits.h>

#include "xconf.h"
#include "param-configer.h"
#include "crypto/crypto-base64.h"
#include "nmap-service/read-service-probes.h"

#include "templ/templ-payloads.h"
#include "templ/templ-opts.h"

#include "util/mas-safefunc.h"
#include "util/logger.h"
#include "util/unusedparm.h"
#include "util/mas-malloc.h"

#include "massip/massip-addr.h"
#include "massip/massip.h"
#include "massip/massip-addr.h"
#include "massip/massip-parse.h"
#include "massip/massip-port.h"

#ifdef WIN32
#include <direct.h>
#define getcwd _getcwd
#else
#include <unistd.h>
#endif

#if defined(_MSC_VER)
#define strdup _strdup
#endif

/***************************************************************************
 ***************************************************************************/
/*static struct Range top_ports_tcp[] = {
    {80, 80},{23, 23}, {443,443},{21,22},{25,25},{3389,3389},{110,110},
    {445,445},
};
static struct Range top_ports_udp[] = {
    {161, 161}, {631, 631}, {137,138},{123,123},{1434},{445,445},{135,135},
    {67,67},
};
static struct Range top_ports_sctp[] = {
    {7, 7},{9, 9},{20,22},{80,80},{179,179},{443,443},{1167,1167},
};*/


/***************************************************************************
 ***************************************************************************/
void
adapter_get_source_addresses(const struct Xconf *xconf, struct source_t *src)
{
    const struct stack_src_t *ifsrc = &xconf->nic.src;
    static ipv6address mask = {~0ULL, ~0ULL};

    src->ipv4 = ifsrc->ipv4.first;
    src->ipv4_mask = ifsrc->ipv4.last - ifsrc->ipv4.first;

    src->port = ifsrc->port.first;
    src->port_mask = ifsrc->port.last - ifsrc->port.first;

    src->ipv6 = ifsrc->ipv6.first;

    /* TODO: currently supports only a single address. This needs to
     * be fixed to support a list of addresses */
    src->ipv6_mask = mask;
}


/***************************************************************************
 ***************************************************************************/
static unsigned
count_cidr6_bits(struct Range6 *range, bool *exact)
{
    uint64_t i;

    /* for the comments of this function, see  count_cidr_bits */
    *exact = false;
    
    for (i=0; i<128; i++) {
        uint64_t mask_hi;
        uint64_t mask_lo;
        if (i < 64) {
            mask_hi = 0xFFFFFFFFffffffffull >> i;
            mask_lo = 0xFFFFFFFFffffffffull;
        } else {
            mask_hi = 0;
            mask_lo = 0xFFFFFFFFffffffffull >> (i - 64);
        }
        if ((range->begin.hi & mask_hi) != 0 || (range->begin.lo & mask_lo) != 0) {
            continue;
        }
        if ((range->begin.hi & ~mask_hi) == (range->end.hi & ~mask_hi) &&
                (range->begin.lo & ~mask_lo) == (range->end.lo & ~mask_lo)) {
            if (((range->end.hi & mask_hi) == mask_hi) && ((range->end.lo & mask_lo) == mask_lo)) {
                *exact = true;
                return (unsigned) i;
            }
        } else {
            *exact = false;
            range->begin.hi = range->begin.hi + mask_hi;
            if (range->begin.lo >= 0xffffffffffffffff - 1 - mask_lo) {
                range->begin.hi += 1;
            }
            range->begin.lo = range->begin.lo + mask_lo + 1;
            return (unsigned) i;
        }
    }
    range->begin.lo = range->begin.lo + 1;
    if (range->begin.lo == 0) {
        range->begin.hi = range->begin.hi + 1;
    }
    return 128;
}

/***************************************************************************
 ***************************************************************************/
void
xconf_save_state(struct Xconf *xconf)
{
    char filename[512];
    FILE *fp;

    safe_strcpy(filename, sizeof(filename), "paused.conf");
    fprintf(stderr, "                                   "
                    "                                   \r");
    fprintf(stderr, "saving resume file to: %s\n", filename);

    fp = fopen(filename, "wt");
    if (fp == NULL) {
        fprintf(stderr, "[-] FAIL: saving resume file\n");
        fprintf(stderr, "[-] %s: %s\n", filename, strerror(errno));
        return;
    }

    
    xconf_echo(xconf, fp);

    fclose(fp);
}


static int SET_stateless_banners(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->is_stateless_banners || xconf->echo_all)
            fprintf(xconf->echo, "stateless-banners = %s\n", xconf->is_stateless_banners?"true":"false");
       return 0;
    }
    xconf->is_stateless_banners = parseBoolean(value);

    if (xconf->is_stateless_banners) {
        fprintf(stderr, "FAIL %s: can not specify banners mode and stateless-banners mode at the same time.\n", name);
        fprintf(stderr, "Hint: banners mode gets banners with TCP\\IP stack in user mode.\n");
        fprintf(stderr, "Hint: stateless-banners mode gets banners in stateless. \n");
        return CONF_ERR;
    }

    return CONF_OK;
}

static int SET_scan_module(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->scan_module || xconf->echo_all){
            if (xconf->scan_module)
                fprintf(xconf->echo, "scan-module = %s\n", xconf->scan_module->name);
            else
                fprintf(xconf->echo, "scan-module = \n");
        }
        return 0;
    }

    xconf->scan_module = get_scan_module_by_name(value);
    if(!xconf->scan_module){
        fprintf(stderr, "FAIL %s: no such scan module named %s\n", name, value);
        return CONF_ERR;
    }

    return CONF_OK;
}

static int SET_stateless_probe(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->stateless_probe || xconf->echo_all){
            if (xconf->stateless_probe)
                fprintf(xconf->echo, "stateless-probe = %s\n", xconf->stateless_probe->name);
            else
                fprintf(xconf->echo, "stateless-probe = \n");
        }
        return 0;
    }

    if(!xconf->is_stateless_banners){
        fprintf(stderr, "FAIL %s: use --stateless-banners mode before specify %s\n", value, name);
        return CONF_ERR;
    }

    xconf->stateless_probe = get_stateless_probe(value);
    if(!xconf->stateless_probe){
        fprintf(stderr, "FAIL %s: no such stateless probe\n", value);
        return CONF_ERR;
    }

    return CONF_OK;
}

static int SET_show(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->is_show_failed || xconf->echo_all){
            fprintf(xconf->echo, "show failed = %s\n",
                xconf->is_show_failed?"true":"false");
        }
        if (xconf->is_show_report || xconf->echo_all){
            fprintf(xconf->echo, "show report = %s\n",
                xconf->is_show_report?"true":"false");
        }
        return 0;
    }

    
    if (EQUALS("failed",value)||EQUALS("fail",value)) {
        xconf->is_show_failed = true;
    } else if (EQUALS("report",value)) {
        xconf->is_show_report = true;
    } else {
        fprintf(stderr, "FAIL %s: no item named %s\n", name, value);
        return CONF_ERR;
    }

    return CONF_OK;
}

static int SET_scan_module_args(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->scan_module_args[0] || xconf->echo_all){
            fprintf(xconf->echo, "scan-module-args = %s\n", xconf->scan_module_args);
        }
        return 0;
    }

    
    unsigned value_len = strlen(value);
    if (value_len >= SCAN_MODULE_ARGS_LEN) {
        fprintf(stderr, "FAIL %s: length of args is too long\n", name);
        fprintf(stderr, "Hint: length of %s args must be no more than %u.\n",
            name, SCAN_MODULE_ARGS_LEN-1);
        return CONF_ERR;
    }

    memcpy(xconf->scan_module_args, value, value_len);
    return CONF_OK;
}

static int SET_probe_args(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->stateless_probe_args[0] || xconf->echo_all){
            fprintf(xconf->echo, "stateless-probe-args = %s\n", xconf->stateless_probe_args);
        }
        return 0;
    }

    
    unsigned value_len = strlen(value);
    if (value_len >= STATELESS_PROBE_ARGS_LEN) {
        fprintf(stderr, "FAIL %s: length of args is too long\n", name);
        fprintf(stderr, "Hint: length of %s args must be no more than %u.\n",
            name, STATELESS_PROBE_ARGS_LEN-1);
        return CONF_ERR;
    }

    memcpy(xconf->stateless_probe_args, value, value_len);
    return CONF_OK;
}

static int SET_list_scan_modules(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
       return 0;
    }
    xconf->op = parseBoolean(value)?Operation_ListScanModules:xconf->op;
    return CONF_OK;
}

static int SET_list_probes(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
       return 0;
    }
    xconf->op = parseBoolean(value)?Operation_ListProbes:xconf->op;
    return CONF_OK;
}

static int SET_iflist(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->op==Operation_ReadRange || xconf->echo_all)
            fprintf(xconf->echo, "iflist = %s\n",
                xconf->op==Operation_ListAdapters?"true":"false");
        return 0;
    }

    if (parseBoolean(value))
        xconf->op = Operation_ListAdapters;
    return CONF_OK;
}

static int SET_list_target(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);

    if (xconf->echo) {
        if (xconf->op==Operation_ListTargets || xconf->echo_all)
            fprintf(xconf->echo, "list-scan = %s\n",
                xconf->op==Operation_ListTargets?"true":"false");
        return 0;
    }

    /* Read in a binary file instead of scanning the network*/
    xconf->op = Operation_ListTargets;

    return CONF_OK;
}

static int SET_read_range(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->op==Operation_ReadRange || xconf->echo_all)
            fprintf(xconf->echo, "read-range = %s\n",
                xconf->op==Operation_ReadRange?"true":"false");
        return 0;
    }

    if (parseBoolean(value))
        xconf->op = Operation_ReadRange;

    return CONF_OK;
}

static int SET_pfring(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_pfring || xconf->echo_all)
            fprintf(xconf->echo, "pfring = %s\n", xconf->is_pfring?"true":"false");
        return 0;
    }

    xconf->is_pfring = parseBoolean(value);

    return CONF_OK;
}

static int SET_nodedup(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->is_nodedup || xconf->echo_all) {
            fprintf(xconf->echo, "nodedup = %s\n", xconf->is_nodedup?"true":"false");
        }
       return 0;
    }

    xconf->is_nodedup = parseBoolean(value);

    return CONF_OK;
}

static int SET_badsum(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->nmap.badsum || xconf->echo_all)
            fprintf(xconf->echo, "badsum = %s\n", xconf->nmap.badsum?"true":"false");
       return 0;
    }

    xconf->nmap.badsum = parseBoolean(value);

    return CONF_OK;
}

static int SET_ttl(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->nmap.ttl || xconf->echo_all)
            fprintf(xconf->echo, "ttl = %u\n", xconf->nmap.ttl);
       return 0;
    }

    unsigned x = parseInt(value);
    if (x >= 256) {
        fprintf(stderr, "error: %s=<n>: expected number less than 256\n", name);
        return CONF_ERR;
    } else {
        xconf->nmap.ttl = x;
    }

    return CONF_OK;
}

static int SET_dedup_win(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->dedup_win!=1000000 || xconf->echo_all)
            fprintf(xconf->echo, "dedup-win = %u\n", xconf->dedup_win);
       return 0;
    }

    if (parseInt(value)<=0) {
        fprintf(stderr, "FAIL: %s: dedup-win must > 0.\n", name);
        return CONF_ERR;
    }

    xconf->dedup_win = parseInt(value);

    return CONF_OK;
}

static int SET_stack_buf_count(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->stack_buf_count!=16384 || xconf->echo_all) {
            fprintf(xconf->echo, "stack-buf-count = %u\n", xconf->stack_buf_count);
        }
       return 0;
    }

    uint64_t v = parseInt(value);
    if (v<=0) {
        fprintf(stderr, "FAIL: %s: stack-buf-count must > 0.\n", value);
        return CONF_ERR;
    } else if (!is_power_of_two(v)) {
        fprintf(stderr, "FAIL: %s: stack-buf-count must be power of 2.\n", value);
        return CONF_ERR;
    } else if (v>RTE_RING_SZ_MASK) {
        fprintf(stderr, "FAIL: %s: stack-buf-count exceeded size limit.\n", value);
        return CONF_ERR;
    }

    xconf->stack_buf_count = v;

    return CONF_OK;
}

static int SET_wait(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->wait==INT_MAX)
            fprintf(xconf->echo, "wait = forever\n");
        else
            fprintf(xconf->echo, "wait = %u\n", xconf->wait);
        return 0;
    }

    if (EQUALS("forever", value))
        xconf->wait =  INT_MAX;
    else
        xconf->wait = (unsigned)parseInt(value);

    return CONF_OK;
}

static int SET_thread_count(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        fprintf(xconf->echo, "transmit-thread-count = %u\n", xconf->tx_thread_count);
        fprintf(xconf->echo, "receive-thread-count  = 1 (always)\n");
        return 0;
    }

    unsigned count = parseInt(value);
    if (count==0) {
        fprintf(stderr, "FAIL: %s: transmit thread count cannot be zero.\n", name);
        return CONF_ERR;
    }

    xconf->tx_thread_count = count;

    return CONF_OK;
}

static int SET_debug_interface(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->op==Operation_DebugIF || xconf->echo_all)
            fprintf(xconf->echo, "debug interface = %s\n",
                xconf->op==Operation_DebugIF?"true":"false");
       return 0;
    }
    if (parseBoolean(value))
        xconf->op = Operation_DebugIF;
    return CONF_OK;
}

static int SET_adapter(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->nic.ifname[0] || xconf->echo_all) {
            fprintf(xconf->echo, "adapter = %s\n", xconf->nic.ifname);
        }
        return 0;
    }

    if (xconf->nic.ifname[0]) {
        fprintf(stderr, "CONF: overwriting \"adapter=%s\"\n", xconf->nic.ifname);
    }
    snprintf(  xconf->nic.ifname, sizeof(xconf->nic.ifname),
        "%s", value);

    return CONF_OK;
}

static int SET_source_ip(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {

        if (xconf->nic.src.ipv4.first) {
            ipaddress_formatted_t ipv4_first =
                ipv4address_fmt((ipv4address)(xconf->nic.src.ipv4.first));
            ipaddress_formatted_t ipv4_last =
                ipv4address_fmt((ipv4address)(xconf->nic.src.ipv4.last));
            fprintf(xconf->echo, "source IPv4 first = %s\n", ipv4_first.string);
            fprintf(xconf->echo, "source IPv4 last = %s\n", ipv4_last.string);
            fprintf(xconf->echo, "source IPv4 range = %u\n", xconf->nic.src.ipv4.range);
        }

        if (xconf->nic.src.ipv6.first.hi && xconf->nic.src.ipv6.first.lo) {
            ipaddress_formatted_t ipv6_first =
                ipv6address_fmt((ipv6address)(xconf->nic.src.ipv6.first));
            ipaddress_formatted_t ipv6_last =
                ipv6address_fmt((ipv6address)(xconf->nic.src.ipv6.last));
            fprintf(xconf->echo, "source IPv6 first = %s\n", ipv6_first.string);
            fprintf(xconf->echo, "source IPv6 last = %s\n", ipv6_last.string);
            fprintf(xconf->echo, "source IPv6 range = %u\n", xconf->nic.src.ipv6.range);
        }

        return 0;
    }

    /* Send packets FROM this IP address */
    struct Range range;
    struct Range6 range6;
    int err;

    /* Grab the next IPv4 or IPv6 range */
    err = massip_parse_range(value, 0, 0, &range, &range6);
    switch (err) {
        case Ipv4_Address:
            /* If more than one IP address given, make the range is
                * an even power of two (1, 2, 4, 8, 16, ...) */
            if (!is_power_of_two((uint64_t)range.end - range.begin + 1)) {
                fprintf(stderr, "FAIL: range must be even power of two: %s=%s\n",
                    name, value);
                return CONF_ERR;
            }
            xconf->nic.src.ipv4.first = range.begin;
            xconf->nic.src.ipv4.last = range.end;
            xconf->nic.src.ipv4.range = range.end - range.begin + 1;
            break;
        case Ipv6_Address:
            xconf->nic.src.ipv6.first = range6.begin;
            xconf->nic.src.ipv6.last = range6.end;
            xconf->nic.src.ipv6.range = 1; /* TODO: add support for more than one source */
            break;
        default:
            fprintf(stderr, "FAIL: bad source IP address: %s=%s\n",
                name, value);
            fprintf(stderr, "hint   addresses look like \"192.168.1.23\" or \"2001:db8:1::1ce9\".\n");
            return CONF_ERR;
    }

    return CONF_OK;
}

static int SET_source_port(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->nic.src.port.first) {
            fprintf(xconf->echo, "source port first = %u\n", xconf->nic.src.port.first);
            fprintf(xconf->echo, "source port last = %u\n", xconf->nic.src.port.last);
            fprintf(xconf->echo, "source port range = %u\n", xconf->nic.src.port.range);
        }
        return 0;
    }

    /* Send packets FROM this port number */
    unsigned is_error = 0;
    struct RangeList ports = {0};
    memset(&ports, 0, sizeof(ports));

    rangelist_parse_ports(&ports, value, &is_error, 0);

    /* Check if there was an error in parsing */
    if (is_error) {
        fprintf(stderr, "FAIL: bad source port specification: %s\n", name);
        return CONF_ERR;
    }

    /* Only allow one range of ports */
    if (ports.count != 1) {
        fprintf(stderr, "FAIL: only one '%s' range may be specified, found %u ranges\n",
            name, ports.count);
        return CONF_ERR;
    }

    /* verify range is even power of 2 (1, 2, 4, 8, 16, ...) */
    if (!is_power_of_two(ports.list[0].end - ports.list[0].begin + 1)) {
        fprintf(stderr, "FAIL: source port range must be even power of two: %s=%s\n",
            name, value);
        return CONF_ERR;
    }

    xconf->nic.src.port.first = ports.list[0].begin;
    xconf->nic.src.port.last = ports.list[0].end;
    xconf->nic.src.port.range = ports.list[0].end - ports.list[0].begin + 1;

    return CONF_OK;
}

static int SET_target_output(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        fprintf(xconf->echo, "ports = ");
        /* Disable comma generation for the first element */
        unsigned i;
        unsigned l = 0;
        l = 0;
        for (i=0; i<xconf->targets.ports.count; i++) {
            struct Range range = xconf->targets.ports.list[i];
            do {
                struct Range rrange = range;
                unsigned done = 0;
                if (l)
                    fprintf(xconf->echo, ",");
                l = 1;
                if (rrange.begin >= Templ_ICMP_echo) {
                    rrange.begin -= Templ_ICMP_echo;
                    rrange.end -= Templ_ICMP_echo;
                    fprintf(xconf->echo,"I:");
                    done = 1;
                } else if (rrange.begin >= Templ_SCTP) {
                    rrange.begin -= Templ_SCTP;
                    rrange.end -= Templ_SCTP;
                    fprintf(xconf->echo,"S:");
                    range.begin = Templ_ICMP_echo;
                } else if (rrange.begin >= Templ_UDP) {
                    rrange.begin -= Templ_UDP;
                    rrange.end -= Templ_UDP;
                    fprintf(xconf->echo,"U:");
                    range.begin = Templ_SCTP;
                } else if (Templ_Oproto_first <= rrange.begin && rrange.begin <= Templ_Oproto_last) {
                    rrange.begin -= Templ_Oproto_first;
                    rrange.end -= Templ_Oproto_first;
                    fprintf(xconf->echo, "O:");
                    range.begin = Templ_Oproto_first;
                } else
                    range.begin = Templ_UDP;
                rrange.end = min(rrange.end, 65535);
                if (rrange.begin == rrange.end)
                    fprintf(xconf->echo, "%u", rrange.begin);
                else
                    fprintf(xconf->echo, "%u-%u", rrange.begin, rrange.end);
                if (done)
                    break;
            } while (range.begin <= range.end);
        }
        fprintf(xconf->echo, "\n");
        /*
        * IPv4 address targets
        */
        for (i=0; i<xconf->targets.ipv4.count; i++) {
            unsigned prefix_bits;
            struct Range range = xconf->targets.ipv4.list[i];

            if (range.begin == range.end) {
                fprintf(xconf->echo, "range = %u.%u.%u.%u",
                        (range.begin>>24)&0xFF,
                        (range.begin>>16)&0xFF,
                        (range.begin>> 8)&0xFF,
                        (range.begin>> 0)&0xFF
                        );
            } else if (range_is_cidr(range, &prefix_bits)) {
                fprintf(xconf->echo, "range = %u.%u.%u.%u/%u",
                        (range.begin>>24)&0xFF,
                        (range.begin>>16)&0xFF,
                        (range.begin>> 8)&0xFF,
                        (range.begin>> 0)&0xFF,
                        prefix_bits
                        );

            } else {
                fprintf(xconf->echo, "range = %u.%u.%u.%u-%u.%u.%u.%u",
                        (range.begin>>24)&0xFF,
                        (range.begin>>16)&0xFF,
                        (range.begin>> 8)&0xFF,
                        (range.begin>> 0)&0xFF,
                        (range.end>>24)&0xFF,
                        (range.end>>16)&0xFF,
                        (range.end>> 8)&0xFF,
                        (range.end>> 0)&0xFF
                        );
            }
            fprintf(xconf->echo, "\n");
        }
        for (i=0; i<xconf->targets.ipv6.count; i++) {
            bool exact = false;
            struct Range6 range = xconf->targets.ipv6.list[i];
            ipaddress_formatted_t fmt = ipv6address_fmt(range.begin);
            
            fprintf(xconf->echo, "range = %s", fmt.string);
            if (!ipv6address_is_equal(range.begin, range.end)) {
                unsigned cidr_bits = count_cidr6_bits(&range, &exact);
                
                if (exact && cidr_bits) {
                    fprintf(xconf->echo, "/%u", cidr_bits);
                } else {
                    fmt = ipv6address_fmt(range.end);
                    fprintf(xconf->echo, "-%s", fmt.string);
                }
            }
            fprintf(xconf->echo, "\n");
        }
    }

    return CONF_OK;
}

static int SET_target_ip(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }
    
    int err;
    err = massip_add_target_string(&xconf->targets, value);
    if (err) {
        fprintf(stderr, "ERROR: bad IP address/range: %s\n", value);
        return CONF_ERR;
    }

    if (xconf->op == 0)
        xconf->op = Operation_Scan;

    return CONF_OK;
}

static int SET_adapter_vlan(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->nic.is_vlan || xconf->echo_all) {
            if (xconf->nic.is_vlan)
                fprintf(xconf->echo, "vlan id = %u\n", xconf->nic.vlan_id);
            else
                fprintf(xconf->echo, "use vlan = false\n");
        }
        return 0;
    }
    
    xconf->nic.is_vlan = 1;
    xconf->nic.vlan_id = (unsigned)parseInt(value);

    return CONF_OK;
}

static int SET_target_port(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }
    
    unsigned is_error = 0;
    int err = 0;

    rangelist_parse_ports(&xconf->targets.ports, value, &is_error, 0);

    if (is_error || err) {
        fprintf(stderr, "[-] FAIL: bad target port: %s\n", value);
        fprintf(stderr, "    Hint: a port is a number [0..65535]\n");
        return CONF_ERR;
    }

    if (xconf->op == 0)
        xconf->op = Operation_Scan;

    return CONF_OK;
}

static int SET_exclude_ip(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    int err;
    err = massip_add_target_string(&xconf->exclude, value);
    if (err) {
        fprintf(stderr, "ERROR: bad exclude address/range: %s\n", value);
        return CONF_ERR;
    }

    if (xconf->op == 0)
        xconf->op = Operation_Scan;
    
    return CONF_OK;
}

static int SET_exclude_port(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }
    unsigned defaultrange = 0;
    int err;

    err = massip_add_port_string(&xconf->exclude, value, defaultrange);
    if (err) {
        fprintf(stderr, "[-] FAIL: bad exclude port: %s\n", value);
        fprintf(stderr, "    Hint: a port is a number [0..65535]\n");
        return CONF_ERR;
    }
    if (xconf->op == 0)
        xconf->op = Operation_Scan;
    
    return CONF_OK;
}

static int SET_include_file(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    int err;
    const char *filename = value;

    err = massip_parse_file(&xconf->targets, filename);
    if (err) {
        fprintf(stderr, "[-] FAIL: error reading from include file\n");
        return CONF_ERR;
    }
    if (xconf->op == 0)
        xconf->op = Operation_Scan;
    
    return CONF_OK;
}

static int SET_exclude_file(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    unsigned count1 = xconf->exclude.ipv4.count;
    unsigned count2;
    int err;
    const char *filename = value;

    // LOG(1, "EXCLUDING: %s\n", value);
    err = massip_parse_file(&xconf->exclude, filename);
    if (err) {
        fprintf(stderr, "[-] FAIL: error reading from exclude file\n");
        return CONF_ERR;
    }
    /* Detect if this file has made any change, otherwise don't print
        * a message */
    count2 = xconf->exclude.ipv4.count;
    if (count2 - count1)
        fprintf(stderr, "%s: excluding %u ranges from file\n",
            value, count2 - count1);
    
    return CONF_OK;
}

static int SET_source_mac(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->nic.my_mac_count) {
            fprintf(xconf->echo, "source mac = %s\n",
                macaddress_fmt(xconf->nic.source_mac).string);
        }
        return 0;
    }

    /* Send packets FROM this MAC address */
    macaddress_t source_mac;
    int err;

    err = parse_mac_address(value, &source_mac);
    if (err) {
        fprintf(stderr, "[-] CONF: bad MAC address: %s = %s\n",
            name, value);
        return CONF_ERR;
    }

    /* Check for duplicates */
    if (macaddress_is_equal(xconf->nic.source_mac, source_mac)) {
        /* suppresses warning message about duplicate MAC addresses if
            * they are in fact the same */
        return CONF_OK;
    }

    /* Warn if we are overwriting a Mac address */
    if (xconf->nic.my_mac_count != 0) {
        ipaddress_formatted_t fmt1 = macaddress_fmt(xconf->nic.source_mac);
        ipaddress_formatted_t fmt2 = macaddress_fmt(source_mac);
        fprintf(stderr, "[-] WARNING: overwriting MAC address, was %s, now %s\n",
            fmt1.string,
            fmt2.string);
    }

    xconf->nic.source_mac = source_mac;
    xconf->nic.my_mac_count = 1;

    return CONF_OK;
}

static int SET_router_ip(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->nic.router_ip) {
            ipaddress_formatted_t router_ip =
                ipv4address_fmt(xconf->nic.router_ip);
            fprintf(xconf->echo, "router ip first = %s\n", router_ip.string);
        }

        return 0;
    }

    /* Send packets FROM this IP address */
    struct Range range;

    range = range_parse_ipv4(value, 0, 0);

    /* Check for bad format */
    if (range.begin != range.end) {
        fprintf(stderr, "FAIL: bad source IPv4 address: %s=%s\n", name, value);
        fprintf(stderr, "hint   addresses look like \"19.168.1.23\"\n");
        return CONF_ERR;
    }

    xconf->nic.router_ip = range.begin;

    return CONF_OK;
}

static int SET_router_mac(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->nic.router_mac_ipv4.addr[0]) {
            fprintf(xconf->echo, "IPv4 router mac = %s\n",
                macaddress_fmt(xconf->nic.router_mac_ipv4).string);
        }

        if (xconf->nic.router_mac_ipv6.addr[0]) {
            fprintf(xconf->echo, "IPv6 router mac = %s\n",
                macaddress_fmt(xconf->nic.router_mac_ipv6).string);
        }

        return 0;
    }

    macaddress_t router_mac;
    int err;
    err = parse_mac_address(value, &router_mac);
    if (err) {
        fprintf(stderr, "[-] CONF: bad MAC address: %s = %s\n", name, value);
        return CONF_ERR;
    }
    if (EQUALS("router-mac-ipv4", name))
        xconf->nic.router_mac_ipv4 = router_mac;
    else if (EQUALS("router-mac-ipv6", name))
        xconf->nic.router_mac_ipv6 = router_mac;
    else {
        xconf->nic.router_mac_ipv4 = router_mac;
        xconf->nic.router_mac_ipv6 = router_mac;
    }

    return CONF_OK;
}

/**
 * read conf file and set params directly
*/
static int SET_read_conf(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        return 0;
    }

    FILE *fp;
    char line[65536];

    fp = fopen(value, "rt");
    if (fp == NULL) {
        char dir[512];
        char *x;
        
        fprintf(stderr, "[-] FAIL: reading configuration file\n");
        fprintf(stderr, "[-] %s: %s\n", value, strerror(errno));

        x = getcwd(dir, sizeof(dir));
        if (x)
            fprintf(stderr, "[-] cwd = %s\n", dir);
        return CONF_ERR;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *name;
        char *value;

        trim(line, sizeof(line));

        if (ispunct(line[0] & 0xFF) || line[0] == '\0')
            continue;

        name = line;
        value = strchr(line, '=');
        if (value == NULL)
            continue;
        *value = '\0';
        value++;
        trim(name, sizeof(line));
        trim(value, sizeof(line));

        xconf_set_parameter(xconf, name, value);
    }

    fclose(fp);

    return CONF_OK;
}

static int SET_packet_trace(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->nmap.packet_trace || xconf->echo_all)
            fprintf(xconf->echo, "packet-trace = %s\n",
                xconf->nmap.packet_trace?"true":"false");
        return 0;
    }
    xconf->nmap.packet_trace = parseBoolean(value);
    return CONF_OK;
}

static int SET_ndjson_status(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_status_ndjson || xconf->echo_all)
            fprintf(xconf->echo, "ndjson-status = %s\n", xconf->is_status_ndjson?"true":"false");
        return 0;
    }
    xconf->is_status_ndjson = parseBoolean(value);
    return CONF_OK;
}

static int SET_min_packet(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->min_packet_size != 60 || xconf->echo_all)
            fprintf(xconf->echo, "min-packet = %u\n", xconf->min_packet_size);
        return 0;
    }
    xconf->min_packet_size = (unsigned)parseInt(value);
    return CONF_OK;
}

static int SET_nmap_data_length(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    
    if (xconf->echo) {
        if (xconf->nmap.data_length || xconf->echo_all)
            fprintf(xconf->echo, "nmap-data-length = %u\n", xconf->nmap.data_length);
        return 0;
    }
    
    unsigned x = parseInt(value);
    if (x >= 1514 - 14 - 40) {
        fprintf(stderr, "error: %s=<n>: expected number less than 1500\n", name);
        return CONF_ERR;
    } else {
        xconf->nmap.data_length = x;
    }

    return CONF_OK;
}

static int SET_nmap_datadir(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    
    if (xconf->echo) {
        if (xconf->nmap.datadir[0] || xconf->echo_all)
            fprintf(xconf->echo, "nmap-datadir = %s\n", xconf->nmap.datadir);
        return 0;
    }
    
    safe_strcpy(xconf->nmap.datadir, sizeof(xconf->nmap.datadir), value);

    return CONF_OK;
}

static int SET_nmap_payloads(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    
    if (xconf->echo) {
        if ((xconf->payloads.nmap_payloads_filename && xconf->payloads.nmap_payloads_filename[0]) || xconf->echo_all)
            fprintf(xconf->echo, "nmap-payloads = %s\n", xconf->payloads.nmap_payloads_filename);
        return 0;
    }
    
    if (xconf->payloads.nmap_payloads_filename)
        free(xconf->payloads.nmap_payloads_filename);
    xconf->payloads.nmap_payloads_filename = strdup(value);

    return CONF_OK;
}

static int SET_nmap_service_probes(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    
    if (xconf->echo) {
        if ((xconf->payloads.nmap_service_probes_filename && xconf->payloads.nmap_service_probes_filename[0]) || xconf->echo_all)
            fprintf(xconf->echo, "nmap-service-probes = %s\n", xconf->payloads.nmap_service_probes_filename);
        return 0;
    }
    
    if (xconf->payloads.nmap_service_probes_filename)
        free(xconf->payloads.nmap_service_probes_filename);
    xconf->payloads.nmap_service_probes_filename = strdup(value);
    
    
    return CONF_OK;
}

static int SET_offline(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_offline || xconf->echo_all)
            fprintf(xconf->echo, "offline = %s\n", xconf->is_offline?"true":"false");
        return 0;
    }
    xconf->is_offline = parseBoolean(value);
    return CONF_OK;
}

/* Specifies a 'libpcap' file where the received packets will be written.
 * This is useful while debugging so that we can see what exactly is
 * going on. It's also an alternate mode for getting output from this
 * program. Instead of relying upon this program's determination of what
 * ports are open or closed, you can instead simply parse this capture
 * file yourself and make your own determination */
static int SET_pcap_filename(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->pcap_filename[0])
            fprintf(xconf->echo, "pcap-filename = %s\n", xconf->pcap_filename);
        return 0;
    }
    if (value)
        safe_strcpy(xconf->pcap_filename, sizeof(xconf->pcap_filename), value);
    return CONF_OK;
}

/* Specifies a 'libpcap' file from which to read packet-payloads. The payloads found
 * in this file will serve as the template for spewing out custom packets. There are
 * other options that can set payloads as well, like "--nmap-payloads" for reading
 * their custom payload file, as well as the various "hello" options for specifying
 * the string sent to the server once a TCP connection has been established. */
static int SET_pcap_payloads(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if ((xconf->payloads.pcap_payloads_filename && xconf->payloads.pcap_payloads_filename[0]) || xconf->echo_all)
            fprintf(xconf->echo, "pcap-payloads = %s\n", xconf->payloads.pcap_payloads_filename);
        return 0;
    }
    
    if (xconf->payloads.pcap_payloads_filename)
        free(xconf->payloads.pcap_payloads_filename);
    xconf->payloads.pcap_payloads_filename = strdup(value);
    
    /* file will be loaded in "load_database_files()" */
    
    return CONF_OK;
}

static int SET_echo(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->echo_all)
            fprintf(xconf->echo, "echo-all = %s\n", xconf->echo?"true":"false");
        return 0;
    }
    
    if (EQUALS("echo", name) && parseBoolean(value))
        xconf->op = Operation_Echo;
    else if (EQUALS("echo-all", name) && parseBoolean(value)) {
        xconf->op = Operation_Echo;
        xconf->echo_all = 1;
    }
    else if (EQUALS("echo-cidr", name) && parseBoolean(value))
        xconf->op = Operation_EchoCidr;
    
    return CONF_OK;
}

static int SET_lan_mode(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_lan_mode||xconf->echo_all)
            fprintf(xconf->echo, "LAN mode = %s\n", xconf->is_lan_mode?"true":"false");
        return 0;
    }
    
    xconf->is_lan_mode = parseBoolean(value);
    SET_router_mac(xconf, "router-mac", "ff-ff-ff-ff-ff-ff");
    
    return CONF_OK;
}

static int SET_rate(struct Xconf *xconf, const char *name, const char *value)
{
    double rate = 0.0;
    double point = 10.0;
    unsigned i;
    
    if (xconf->echo) {
        if ((unsigned)(xconf->max_rate * 100000) % 100000) {
            /* print as floating point number, which is rare */
            fprintf(xconf->echo, "rate = %f\n", xconf->max_rate);
        } else {
            /* pretty print as just an integer, which is what most people
             * expect */
            fprintf(xconf->echo, "rate = %-10.0f\n", xconf->max_rate);
        }
        return 0;
    }
    
    for (i=0; value[i] && value[i] != '.'; i++) {
        char c = value[i];
        if (c < '0' || '9' < c) {
            fprintf(stderr, "CONF: non-digit in rate spec: %s=%s\n", name, value);
            return CONF_ERR;
        }
        rate = rate * 10.0 + (c - '0');
    }
    
    if (value[i] == '.') {
        i++;
        while (value[i]) {
            char c = value[i];
            if (c < '0' || '9' < c) {
                fprintf(stderr, "CONF: non-digit in rate spec: %s=%s\n",
                        name, value);
                return CONF_ERR;
            }
            rate += (c - '0')/point;
            point *= 10.0;
            value++;
        }
    }
    
    xconf->max_rate = rate;
    return CONF_OK;
}

static int SET_resume_count(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->resume.count || xconf->echo_all) {
            fprintf(xconf->echo, "resume-count = %" PRIu64 "\n", xconf->resume.count);
        }
        return 0;
    }
    xconf->resume.count = parseInt(value);
    return CONF_OK;
}

static int SET_resume_index(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->resume.index  || xconf->echo_all) {
            fprintf(xconf->echo, "resume-index = %" PRIu64 "\n", xconf->resume.index);
        }
        return 0;
    }
    xconf->resume.index = parseInt(value);
    return CONF_OK;
}


static int SET_bpf_filter(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->bpf_filter || xconf->echo_all)
            fprintf(xconf->echo, "bpf-filter = %s\n", xconf->bpf_filter);
        return 0;
    }

    size_t len = strlen(value) + 1;
    if (xconf->bpf_filter)
        free(xconf->bpf_filter);
    xconf->bpf_filter = MALLOC(len);
    memcpy(xconf->bpf_filter, value, len);
    
    return CONF_OK;
}


static int SET_seed(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        fprintf(xconf->echo, "seed = %" PRIu64 "\n", xconf->seed);
        return 0;
    }
    if (EQUALS("time", value))
        xconf->seed = time(0);
    else
        xconf->seed = parseInt(value);
    return CONF_OK;
}

static int SET_delimiter(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        fprintf(xconf->echo, "-=-=-=-=-=-\n");
        return 0;
    }
    return CONF_OK;
}

static int SET_version(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }

    const char *cpu = "unknown";
    const char *compiler = "unknown";
    const char *compiler_version = "unknown";
    const char *os = "unknown";
    printf("\n");
    printf(""XTATE_FIRST_UPPER_NAME" version %s\n( %s )\n", 
        XTATE_VERSION,
        XTATE_GITHUB
        );
    printf("Compiled on: %s %s\n", __DATE__, __TIME__);

#if defined(__x86_64) || defined(__x86_64__)
    cpu = "x86";
#endif

#if defined(_MSC_VER)
    #if defined(_M_AMD64) || defined(_M_X64)
        cpu = "x86";
    #elif defined(_M_IX86)
        cpu = "x86";
    #elif defined (_M_ARM_FP)
        cpu = "arm";
    #endif

    {
        int msc_ver = _MSC_VER;

        compiler = "VisualStudio";

        if (msc_ver < 1500)
            compiler_version = "pre2008";
        else if (msc_ver == 1500)
            compiler_version = "2008";
        else if (msc_ver == 1600)
            compiler_version = "2010";
        else if (msc_ver == 1700)
            compiler_version = "2012";
        else if (msc_ver == 1800)
            compiler_version = "2013";
        else
            compiler_version = "post-2013";
    }

    
#elif defined(__GNUC__)
# if defined(__clang__)
    compiler = "clang";
# else
    compiler = "gcc";
# endif
    compiler_version = __VERSION__;

#if defined(i386) || defined(__i386) || defined(__i386__)
    cpu = "x86";
#endif

#if defined(__corei7) || defined(__corei7__)
    cpu = "x86-Corei7";
#endif

#endif

#if defined(WIN32)
    os = "Windows";
#elif defined(__linux__)
    os = "Linux";
#elif defined(__APPLE__)
    os = "Apple";
#elif defined(__MACH__)
    os = "MACH";
#elif defined(__FreeBSD__)
    os = "FreeBSD";
#elif defined(__NetBSD__)
    os = "NetBSD";
#elif defined(unix) || defined(__unix) || defined(__unix__)
    os = "Unix";
#endif

    printf("Compiler: %s %s\n", compiler, compiler_version);
    printf("OS: %s\n", os);
    printf("CPU: %s (%u bits)\n", cpu, (unsigned)(sizeof(void*))*8);

    return CONF_ERR;
}

static int SET_usage(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }

    printf("\n");
    printf("Welcome to "XTATE_FIRST_UPPER_NAME"!\n");
    printf("\n");
    printf("usage: "XTATE_NAME" [options] [-range <IP|RANGE>... -p PORT[,PORT...]]\n");
    printf("\n");
    printf("original examples in xtate:\n");
    printf("    "XTATE_NAME" -p 80,8000-8100 -range 10.0.0.0/8 --rate=10000\n");
    printf("        scan some web ports on 10.x.x.x at 10kpps\n");
    printf("\n");

    return CONF_ERR;
}

static int SET_help(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }

    printf("\nWelcome to "XTATE_FIRST_UPPER_NAME"!\n\n");

    return CONF_ERR;
}

static int SET_log_level(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(value);
    if (xconf->echo) {
        int level = LOG_get_level();
        if (level > 0  || xconf->echo_all)
            fprintf(xconf->echo, "log level = %d\n", level);
        return 0;
    }

    LOG_add_level(strlen(name));
    
    return CONF_OK;
}

static int SET_shard(struct Xconf *xconf, const char *name, const char *value)
{
    unsigned one = 0;
    unsigned of = 0;

    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->shard.of > 1  || xconf->echo_all)
            fprintf(xconf->echo, "shard = %u/%u\n", xconf->shard.one, xconf->shard.of);
        return 0;
    }
    while (isdigit(*value))
        one = one*10 + (*(value++)) - '0';
    while (ispunct(*value))
        value++;
    while (isdigit(*value))
        of = of*10 + (*(value++)) - '0';
    
    if (one < 1) {
        fprintf(stderr, "FAIL: shard index can't be zero\n");
        fprintf(stderr, "hint   it goes like 1/4 2/4 3/4 4/4\n");
        return CONF_ERR;
    }
    if (one > of) {
        fprintf(stderr, "FAIL: shard spec is wrong\n");
        fprintf(stderr, "hint   it goes like 1/4 2/4 3/4 4/4\n");
        return CONF_ERR;
    }
    xconf->shard.one = one;
    xconf->shard.of = of;
    return CONF_OK;
}

static int SET_tcp_mss(struct Xconf *xconf, const char *name, const char *value)
{
    /* h/t @IvreRocks */
    static const unsigned default_mss = 1460;

    if (xconf->echo) {
        if (xconf->templ_opts) {
            switch (xconf->templ_opts->tcp.is_mss) {
                case Default:
                    break;
                case Add:
                    if (xconf->templ_opts->tcp.mss == default_mss)
                        fprintf(xconf->echo, "tcp-mss = %s\n", "enable");
                    else
                        fprintf(xconf->echo, "tcp-mss = %u\n",
                                xconf->templ_opts->tcp.mss);
                    break;
                case Remove:
                    fprintf(xconf->echo, "tcp-mss = %s\n", "disable");
                    break;
                default:
                    break;
            }
        }
        return 0;
    }

    if (xconf->templ_opts == NULL)
        xconf->templ_opts = calloc(1, sizeof(*xconf->templ_opts));

    if (value == 0 || value[0] == '\0') {
        /* no following parameter, so interpret this to mean "enable" */
        xconf->templ_opts->tcp.is_mss = Add;
        xconf->templ_opts->tcp.mss = default_mss; /* 1460 */
    } else if (isBoolean(value)) {
        /* looking for "enable" or "disable", but any boolean works,
         * like "true/false" or "off/on" */
        if (parseBoolean(value)) {
            xconf->templ_opts->tcp.is_mss = Add;
            xconf->templ_opts->tcp.mss = default_mss; /* 1460 */
        } else
            xconf->templ_opts->tcp.is_mss = Remove;
    } else if (isInteger(value)) {
        /* A specific number was specified */
        uint64_t num = parseInt(value);
        if (num >= 0x10000)
            goto fail;
        xconf->templ_opts->tcp.is_mss = Add;
        xconf->templ_opts->tcp.mss = (unsigned)num;
    } else
        goto fail;

    return CONF_OK;
fail:
    fprintf(stderr, "[-] %s: bad value: %s\n", name, value);
    return CONF_ERR;
}

static int SET_tcp_wscale(struct Xconf *xconf, const char *name, const char *value)
{
    static const unsigned default_value = 3;

    if (xconf->echo) {
        if (xconf->templ_opts) {
            switch (xconf->templ_opts->tcp.is_wscale) {
                case Default:
                    break;
                case Add:
                    if (xconf->templ_opts->tcp.wscale == default_value)
                        fprintf(xconf->echo, "tcp-wscale = %s\n", "enable");
                    else
                        fprintf(xconf->echo, "tcp-wscale = %u\n",
                                xconf->templ_opts->tcp.wscale);
                    break;
                case Remove:
                    fprintf(xconf->echo, "tcp-wscale = %s\n", "disable");
                    break;
                default:
                    break;
            }
        }
        return 0;
    }

    if (xconf->templ_opts == NULL)
        xconf->templ_opts = calloc(1, sizeof(*xconf->templ_opts));

    if (value == 0 || value[0] == '\0') {
        xconf->templ_opts->tcp.is_wscale = Add;
        xconf->templ_opts->tcp.wscale = default_value;
    } else if (isBoolean(value)) {
        if (parseBoolean(value)) {
            xconf->templ_opts->tcp.is_wscale = Add;
            xconf->templ_opts->tcp.wscale = default_value;
        } else
            xconf->templ_opts->tcp.is_wscale = Remove;
    } else if (isInteger(value)) {
        uint64_t num = parseInt(value);
        if (num >= 255)
            goto fail;
        xconf->templ_opts->tcp.is_wscale = Add;
        xconf->templ_opts->tcp.wscale = (unsigned)num;
    } else
        goto fail;

    return CONF_OK;
fail:
    fprintf(stderr, "[-] %s: bad value: %s\n", name, value);
    return CONF_ERR;
}

static int SET_tcp_tsecho(struct Xconf *xconf, const char *name, const char *value)
{
    static const unsigned default_value = 0x12345678;

    if (xconf->echo) {
        if (xconf->templ_opts) {
            switch (xconf->templ_opts->tcp.is_tsecho) {
                case Default:
                    break;
                case Add:
                    if (xconf->templ_opts->tcp.tsecho == default_value)
                        fprintf(xconf->echo, "tcp-tsecho = %s\n", "enable");
                    else
                        fprintf(xconf->echo, "tcp-tsecho = %u\n",
                                xconf->templ_opts->tcp.tsecho);
                    break;
                case Remove:
                    fprintf(xconf->echo, "tcp-tsecho = %s\n", "disable");
                    break;
                default:
                    break;
            }
        }
        return 0;
    }

    if (xconf->templ_opts == NULL)
        xconf->templ_opts = calloc(1, sizeof(*xconf->templ_opts));

    if (value == 0 || value[0] == '\0') {
        xconf->templ_opts->tcp.is_tsecho = Add;
        xconf->templ_opts->tcp.tsecho = default_value;
    } else if (isBoolean(value)) {
        if (parseBoolean(value)) {
            xconf->templ_opts->tcp.is_tsecho = Add;
            xconf->templ_opts->tcp.tsecho = default_value;
        } else
            xconf->templ_opts->tcp.is_tsecho = Remove;
    } else if (isInteger(value)) {
        uint64_t num = parseInt(value);
        if (num >= 255)
            goto fail;
        xconf->templ_opts->tcp.is_tsecho = Add;
        xconf->templ_opts->tcp.tsecho = (unsigned)num;
    } else
        goto fail;

    return CONF_OK;
fail:
    fprintf(stderr, "[-] %s: bad value: %s\n", name, value);
    return CONF_ERR;
}

static int SET_tcp_sackok(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->templ_opts) {
            switch (xconf->templ_opts->tcp.is_sackok) {
                case Default:
                    break;
                case Add:
                    fprintf(xconf->echo, "tcp-sackok = %s\n", "enable");
                    break;
                case Remove:
                    fprintf(xconf->echo, "tcp-sackok = %s\n", "disable");
                    break;
                default:
                    break;
            }
        }
        return 0;
    }

    if (xconf->templ_opts == NULL)
        xconf->templ_opts = calloc(1, sizeof(*xconf->templ_opts));

    if (value == 0 || value[0] == '\0') {
        xconf->templ_opts->tcp.is_sackok = Add;
    } else if (isBoolean(value)) {
        if (parseBoolean(value)) {
            xconf->templ_opts->tcp.is_sackok = Add;
        } else
            xconf->templ_opts->tcp.is_sackok = Remove;
    } else if (isInteger(value)) {
        if (parseInt(value) != 0)
            xconf->templ_opts->tcp.is_sackok = Add;
    } else
        goto fail;

    return CONF_OK;
fail:
    fprintf(stderr, "[-] %s: bad value: %s\n", name, value);
    return CONF_ERR;
}

static int SET_blackrock_rounds(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->blackrock_rounds!=14 || xconf->echo_all)
            fprintf(xconf->echo, "blackrock rounds = %u\n", xconf->blackrock_rounds);
        return 0;
    }

    xconf->blackrock_rounds = (unsigned)parseInt(value);
    return CONF_OK;
}

static int SET_send_queue(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_sendq || xconf->echo_all)
            fprintf(xconf->echo, "send queue = %s\n", xconf->is_sendq?"true":"false");
        return 0;
    }

    xconf->is_sendq = parseBoolean(value);
    return CONF_OK;
}

struct ConfigParameter config_parameters[] = {
    {"BASIC",           SET_delimiter,          0,      {0}},

    {"seed",            SET_seed,               0,      {0}},
    {"rate",            SET_rate,               0,      {"max-rate",0}},
    {"wait",            SET_wait,               F_NUMABLE,{"cooldown",0}},
    {"shard",           SET_shard,              0,      {"shards",0}},
    {"tansmit-thread-count", SET_thread_count,  F_NUMABLE, {"tx-count", "tx-num", 0}},
    {"d",               SET_log_level,          F_BOOL, {"dd","ddd","dddd","ddddd",0}},
    {"v",               SET_log_level,          F_BOOL, {"vv","vvv","vvvv","vvvvv",0}},
    {"version",         SET_version,            F_BOOL, {"V",0}},
    {"help",            SET_help,               F_BOOL, {"h", "?",0}},
    {"usage",           SET_usage,              F_BOOL, {0}},

    // {"TARGET:",         SET_delimiter,          0,      {0}},

    {"target-ip",       SET_target_ip,          0,      {"range", "ranges", "dst-ip", "ip",0}},
    {"port",            SET_target_port,        0,      {"p", "tcp-port", "udp-port", 0}},
    {"include-file",    SET_include_file,       0,      {"iL",0}},
    {"exclude",         SET_exclude_ip,         0,      {"exclude-range", "exlude-ranges", "exclude-ip",0}},
    {"exclude-port",    SET_exclude_port,       0,      {"exclude-ports",0}},
    {"exclude-file",    SET_exclude_file,       0,      {0}},

    {"INTERFACE:",      SET_delimiter,          0,      {0}},

    {"adapter",         SET_adapter,            0,      {"if", "interface",0}},
    {"source-ip",       SET_source_ip,          0,      {"src-ip",0}},
    {"source-port",     SET_source_port,        0,      {"src-port",0}},
    {"source-mac",      SET_source_mac,         0,      {"src-mac",0}},
    {"router-ip",       SET_router_ip,          0,      {0}},
    {"router-mac",      SET_router_mac,         0,      {"gateway-mac", "dst-mac", "router-mac-ipv4", "router-mac-ipv6",0}},
    {"adapter-vlan",    SET_adapter_vlan,       F_NUMABLE, {"vlan",0}},
    {"lan-mode",        SET_lan_mode,                F_BOOL, {"local", "lan",0}},

    {"OPERATION:",      SET_delimiter,          0,      {0}},

    {"echo",            SET_echo,               F_BOOL, {"echo-all", "echo-cidr",0}},
    {"iflist",          SET_iflist,             F_BOOL, {"list-interface", "list-adapter",0}},
    {"readrange",       SET_read_range,         F_BOOL, {"readranges", 0}},
    {"listtarget",      SET_list_target,        F_BOOL, {"list-targets",0}},
    {"debug-if",        SET_debug_interface,    F_BOOL, {"debug-interface",0}},

    {"STATUS & OUTPUTT:",SET_delimiter, 0,      {0}},

    {"ndjson-status",   SET_ndjson_status,      F_BOOL, {"status-ndjson", 0}},
    {"pcap-filename",   SET_pcap_filename,      0,      {"pcap",0}},

    {"PAYLOAD:",        SET_delimiter,          0,      {0}},

    {"nmap-datadir",    SET_nmap_datadir,       0,      {"datadir",0}},
    {"nmap-datalength", SET_nmap_data_length,   F_NUMABLE,{"datalength",0}},
    {"nmap-payloads",   SET_nmap_payloads,      0,      {"nmap-payload",0}},
    {"nmap-service-probes",SET_nmap_service_probes, 0,  {"nmap-service-probe",0}},
    {"pcap-payloads",   SET_pcap_payloads,      0,      {"pcap-payload",0}},

    {"STATELESS:",      SET_delimiter,          0,      {0}},

    {"stateless-banners",SET_stateless_banners, F_BOOL, {"stateless", "stateless-banner", "stateless-mode",0}},
    {"stateless-probe", SET_stateless_probe,    0,      {"probe", 0}},
    {"list-probes",     SET_list_probes,        F_BOOL, {"list-probe", 0}},
    {"probe-args",      SET_probe_args,         0,      {"probe-arg", 0}},

    {"SCAN MODULES:",   SET_delimiter,          0,      {0}},

    {"scan-module",     SET_scan_module,        0,      {"scan", 0}},
    {"list-scan-modules",SET_list_scan_modules, F_BOOL, {"list-scan-module", "list-scan",0}},
    {"scan-module-args", SET_scan_module_args,  0,      {"scan-module-arg",0}},
    {"show",            SET_show,               0,      {0}},

    {"PACKET ATTRIBUTE:",SET_delimiter,         0,      {0}},

    {"ttl",             SET_ttl,                F_NUMABLE, {0}},
    {"badsum",          SET_badsum,             F_BOOL, {0}},
    {"tcp-mss",         SET_tcp_mss,            F_NUMABLE, {0}},
    {"tcp-wscale",      SET_tcp_wscale,         F_NUMABLE, {0}},
    {"tcp-tsecho",      SET_tcp_tsecho,         F_NUMABLE, {0}},
    {"tcp-sackok",      SET_tcp_sackok,         F_BOOL, {"tcp-sack",0}},
    {"min-packet",      SET_min_packet,         0,      {"min-pkt",0}},
    {"packet-trace",    SET_packet_trace,       F_BOOL, {"trace-packet",0}},
    {"bpf-filter",      SET_bpf_filter,         0,      {0}},

    {"MISC:",           SET_delimiter,          0,      {0}},

    {"conf",            SET_read_conf,          0,      {"config", "resume",0}},
    {"resume-index",    SET_resume_index,       0,      {0}},
    {"resume-count",    SET_resume_count,       0,      {0}},
    {"offline",         SET_offline,            F_BOOL, {"notransmit", "nosend", "dry-run", 0}},
    {"nodedup",         SET_nodedup,            F_BOOL, {0}},
    {"dedup-win",       SET_dedup_win,          F_NUMABLE, {0}},
    {"stack-buf-count", SET_stack_buf_count,    F_NUMABLE, {"queue-buf-count", "packet-buf-count", 0}},
    {"pfring",          SET_pfring,             F_BOOL, {0}},
    {"send-queue",      SET_send_queue,         F_BOOL, {"sendq", 0}},
    {"blackrock-rounds",SET_blackrock_rounds,   F_NUMABLE, {"blackrock-round",0}},

    /*Put it at last for better "help" output*/
    {"TARGET (IP, PORTS, EXCLUDES)",SET_delimiter, 0,   {0}},
    {"TARGET_OUTPUT",   SET_target_output,      0,      {0}},
    {0}
};

/***************************************************************************
 * Called either from the "command-line" parser when it sees a --param,
 * or from the "config-file" parser for normal options.
 * 
 * Exit process if CONF_ERR happens.
 ***************************************************************************/
void
xconf_set_parameter(struct Xconf *xconf,
                      const char *name, const char *value)
{
    set_one_parameter(xconf, config_parameters, name, value);
}



/***************************************************************************
 ***************************************************************************/
void
load_database_files(struct Xconf *xconf)
{
    const char *filename;
    
    /*
     * "pcap-payloads"
     */
    filename = xconf->payloads.pcap_payloads_filename;
    if (filename) {
        if (xconf->payloads.udp == NULL)
            xconf->payloads.udp = payloads_udp_create();
        if (xconf->payloads.oproto == NULL)
            xconf->payloads.oproto = payloads_udp_create();

        payloads_read_pcap(filename, xconf->payloads.udp, xconf->payloads.oproto);
    }

    /*
     * `--nmap-payloads`
     */
    filename = xconf->payloads.nmap_payloads_filename;
    if (filename) {
        FILE *fp;
        
        fp = fopen(filename, "rt");
        if (fp == NULL) {
            fprintf(stderr, "[-] FAIL: --nmap-payloads\n");
            fprintf(stderr, "[-] %s:%s\n", filename, strerror(errno));
        } else {
            if (xconf->payloads.udp == NULL)
                xconf->payloads.udp = payloads_udp_create();
            
            payloads_udp_readfile(fp, filename, xconf->payloads.udp);
            
            fclose(fp);
        }
    }
    
    /*
     * "nmap-service-probes"
     */
    filename = xconf->payloads.nmap_service_probes_filename;
    if (filename) {
        if (xconf->payloads.probes)
            nmapserviceprobes_free(xconf->payloads.probes);
        
        xconf->payloads.probes = nmapserviceprobes_read_file(filename);
    }
}

/***************************************************************************
 * Read the configuration from the command-line.
 * Called by 'main()' when starting up.
 ***************************************************************************/
void
xconf_command_line(struct Xconf *xconf, int argc, char *argv[])
{
    set_parameters_from_args(xconf, config_parameters, argc, argv);

    if (xconf->shard.of > 1 && xconf->seed == 0) {
        fprintf(stderr, "[-] WARNING: --seed <num> is not specified\n    HINT: all shards must share the same seed\n");
    }
}

/***************************************************************************
 * Prints the current configuration to the command-line then exits.
 * Use#1: create a template file of all settable parameters.
 * Use#2: make sure your configuration was interpreted correctly.
 ***************************************************************************/
void
xconf_echo(struct Xconf *xconf, FILE *fp)
{
    paramters_echo(xconf, fp, config_parameters);
}


/***************************************************************************
 * Prints the list of CIDR to scan to the command-line then exits.
 * Use: provide this list to other tools. Unlike xconf -sL, it keeps
 * the CIDR aggretated format, and does not randomize the order of output.
 * For example, given the starting range of [10.0.0.1-10.0.0.255], this will
 * print all the CIDR ranges that make this up:
 *  10.0.0.1/32
 *  10.0.0.2/31
 *  10.0.0.4/30
 *  10.0.0.8/29
 *  10.0.0.16/28
 *  10.0.0.32/27
 *  10.0.0.64/26
 *  10.0.0.128/25
 ***************************************************************************/
void
xconf_echo_cidr(struct Xconf *xconf, FILE *fp)
{
    unsigned i;

    xconf->echo = fp;

    /*
     * For all IPv4 ranges ...
     */
    for (i=0; i<xconf->targets.ipv4.count; i++) {

        /* Get the next range in the list */
        struct Range range = xconf->targets.ipv4.list[i];

        /* If not a single CIDR range, print all the CIDR ranges
         * needed to completely represent this addres */
        for (;;) {
            unsigned prefix_length;
            struct Range cidr;

            /* Find the largest CIDR range (one that can be specified
             * with a /prefix) at the start of this range. */
            cidr = range_first_cidr(range, &prefix_length);
            fprintf(fp, "%u.%u.%u.%u/%u\n",
                    (cidr.begin>>24)&0xFF,
                    (cidr.begin>>16)&0xFF,
                    (cidr.begin>> 8)&0xFF,
                    (cidr.begin>> 0)&0xFF,
                    prefix_length
                    );

            /* If this is the last range, then stop. There are multiple
             * ways to gets to see if we get to the end, but I think
             * this is the best. */
            if (cidr.end >= range.end)
                break;

            /* If the CIDR range didn't cover the entire range,
             * then remove it from the beginning of the range
             * and process the remainder */
            range.begin = cidr.end+1;
        }
    }

    /*
     * For all IPv6 ranges...
     */
    for (i=0; i<xconf->targets.ipv6.count; i++) {
        struct Range6 range = xconf->targets.ipv6.list[i];
        bool exact = false;
        while (!exact) {
            ipaddress_formatted_t fmt = ipv6address_fmt(range.begin);
            fprintf(fp, "%s", fmt.string);
            if (range.begin.hi == range.end.hi && range.begin.lo == range.end.lo) {
                fprintf(fp, "/128");
                exact = true;
            } else {
                unsigned cidr_bits = count_cidr6_bits(&range, &exact);
                fprintf(fp, "/%u", cidr_bits);
            }
            fprintf(fp, "\n");
        }
    }
}

/***************************************************************************
 ***************************************************************************/
int xconf_contains(const char *x, int argc, char **argv)
{
    int i;

    for (i=0; i<argc; i++) {
        if (strcmp(argv[i], x) == 0)
            return 1;
    }

    return 0;
}
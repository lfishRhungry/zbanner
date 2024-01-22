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
#include "vulncheck/vulncheck.h"
#include "nmap-service/read-service-probes.h"

#include "proto/proto-banner1.h"
#include "proto/masscan-app.h"


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

/**
 * Called if user specified `--top-ports` on the command-line.
 */
static void
config_top_ports(struct Xconf *xconf, unsigned maxports)
{
    unsigned i;
    static const unsigned short top_udp_ports[] = {
        161, /* SNMP - should be found on all network equipment */
        135, /* MS-RPC - should be found on all modern Windows */
        500, /* ISAKMP - for establishing IPsec tunnels */
        137, /* NetBIOS-NameService - should be found on old Windows */
        138, /* NetBIOS-Datagram - should be found on old Windows */
        445, /* SMB datagram service */
        67, /* DHCP */
        53, /* DNS */
        1900, /* UPnP - Microsoft-focused local discovery */
        5353, /* mDNS - Apple-focused local discovery */
        4500, /* nat-t-ike - IPsec NAT traversal */
        514, /* syslog - all Unix machiens */
        69, /* TFTP */
        49152, /* first of modern ephemeral ports */
        631, /* IPP - printing protocol for Linux */
        123, /* NTP network time protocol */
        1434, /* MS-SQL server*/
        520, /* RIP - routers use this protocol sometimes */
        7, /* Echo */
        111, /* SunRPC portmapper */
        2049, /* SunRPC NFS */
        5683, /* COAP */
        11211, /* memcached */
        1701, /* L2TP */
        27960, /* quaked amplifier */
        1645, /* RADIUS */
        1812, /* RADIUS */
        1646, /* RADIUS */
        1813, /* RADIUS */
        3343, /* Microsoft Cluster Services */
        2535, /* MADCAP rfc2730 TODO FIXME */
        
    };

    static const unsigned short top_tcp_ports[] = {
        80, 443, 8080,   /* also web */
        21, 990,     /* FTP, oldie but goodie */
        22,     /* SSH, so much infrastructure */
        23, 992,     /* Telnet, oldie but still around*/
        24,     /* people put things here instead of TelnetSSH*/
        25, 465, 587, 2525,     /* SMTP email*/
        5800, 5900, 5901, /* VNC */
        111,    /* SunRPC */
        139, 445, /* Microsoft Windows networking */
        135,    /* DCEPRC, more Microsoft Windows */
        3389,   /* Microsoft Windows RDP */
        88,     /* Kerberos, also Microsoft windows */
        389, 636,    /* LDAP and MS Win */
        1433,   /* MS SQL */
        53,     /* DNS */
        2083, 2096,   /* cPanel */
        9050,   /* ToR */
        8140,   /* Puppet */
        11211,  /* memcached */
        1098, 1099, /* Java RMI */
        6000, 6001, /* XWindows */
        5060, 5061, /* SIP - session initiation protocool */
        554,    /* RTSP */
        548,    /* AFP */
        

        1,3,4,6,7,9,13,17,19,20,26,30,32,33,37,42,43,49,70,
        79,81,82,83,84,85,89,90,99,100,106,109,110,113,119,125,
        143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,
        301,306,311,340,366,406,407,416,417,425,427,444,458,464,
        465,481,497,500,512,513,514,515,524,541,543,544,545,554,555,563,
        593,616,617,625,631,646,648,666,667,668,683,687,691,700,705,
        711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,
        898,900,901,902,903,911,912,981,987,993,995,999,1000,1001,
        1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,
        1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,
        1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,
        1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,
        1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,
        1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,
        1094,1095,1096,1097,1100,1102,1104,1105,1106,1107,1108,
        1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,
        1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,
        1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,
        1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,
        1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,
        1417,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,
        1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,
        1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,
        1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,
        1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,
        2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,
        2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,
        2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,
        2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,
        2401,2492,2500,2522,2557,2601,2602,2604,2605,2607,2608,2638,
        2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,
        2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,
        3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,
        3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,
        3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,
        3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,
        3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,
        3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,
        4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,
        4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,
        5050,5051,5054,5080,5087,5100,5101,5102,5120,5190,5200,
        5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,
        5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,
        5718,5730,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,
        5877,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,
        5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,
        6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,
        6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,
        6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,
        6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,
        7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,
        7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,
        8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,
        8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,
        8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,
        8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,
        9000,9001,9002,9003,9009,9010,9011,9040,9071,9080,9081,9090,
        9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,
        9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,
        9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,
        10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,
        10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,
        11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,
        14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,
        16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,
        19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,
        20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,
        27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,
        32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,
        32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,
        34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,
        45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,
        49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,
        50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,
        52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,
        57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,
        65129,65389};
    struct RangeList *ports = &xconf->targets.ports;
    static const unsigned max_tcp_ports = sizeof(top_tcp_ports)/sizeof(top_tcp_ports[0]);
    static const unsigned max_udp_ports = sizeof(top_udp_ports)/sizeof(top_udp_ports[0]);


    if (xconf->scan_type.tcp) {
        LOG(2, "[+] adding TCP top-ports = %u\n", maxports);
        for (i=0; i<maxports && i<max_tcp_ports; i++)
            rangelist_add_range_tcp(ports,
                                top_tcp_ports[i],
                                top_tcp_ports[i]);
    }

    if (xconf->scan_type.udp) {
        LOG(2, "[+] adding UDP top-ports = %u\n", maxports);
        for (i=0; i<maxports && i<max_udp_ports; i++)
            rangelist_add_range_udp(ports,
                                top_udp_ports[i],
                                top_udp_ports[i]);
    }

    /* Targets must be sorted after every change, before being used */
    rangelist_sort(ports);
}


static int SET_stateless_banners(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->is_stateless_banners || xconf->echo_all)
            fprintf(xconf->echo, "stateless-banners = %s\n", xconf->is_stateless_banners?"true":"false");
       return 0;
    }
    xconf->is_stateless_banners = parseBoolean(value);

    if (xconf->is_banners && xconf->is_stateless_banners) {
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

static int SET_benchmark(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->op==Operation_Benchmark || xconf->echo_all)
            fprintf(xconf->echo, "benchmark = %s\n",
                xconf->op==Operation_Benchmark?"true":"false");
        return 0;
    }

    if (parseBoolean(value))
        xconf->op = Operation_Benchmark;

    return CONF_OK;
}

static int SET_selftest(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->op==Operation_Selftest || xconf->echo_all)
            fprintf(xconf->echo, "selftest = %s\n",
                xconf->op==Operation_Selftest?"true":"false");
        return 0;
    }

    if (parseBoolean(value))
        xconf->op = Operation_Selftest;

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

static int SET_read_scan(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);

    if (xconf->echo) {
        if (xconf->op==Operation_ReadRange || xconf->echo_all)
            fprintf(xconf->echo, "read-scan = %s\n",
                xconf->op==Operation_ReadRange?"true":"false");
        return 0;
    }

    /* Read in a binary file instead of scanning the network*/
    xconf->op = Operation_ReadScan;
    
    /* Default to reading banners */
    xconf->is_banners = true;
    xconf->is_banners_rawudp = true;

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

/**
 * See proto-oproto.h
 * oproto does nothing now
 * */
static int SET_oproto(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->scan_type.oproto || xconf->echo_all)
            fprintf(xconf->echo, "oproto = %s\n",
                xconf->scan_type.oproto?"true":"false");
        return 0;
    }

    unsigned is_error = 0;
    xconf->scan_type.oproto = 1;
    rangelist_parse_ports(&xconf->targets.ports, value, &is_error, Templ_Oproto_first);
    if (xconf->op == 0)
        xconf->op = Operation_Scan;

    return CONF_OK;
}

static int SET_ping(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->scan_type.ping || xconf->echo_all)
            fprintf(xconf->echo, "ping = %s\n", xconf->scan_type.ping?"true":"false");
        return 0;
    }

    /* Add ICMP ping request */
    struct Range range;
    range.begin = Templ_ICMP_echo;
    range.end = Templ_ICMP_echo;
    rangelist_add_range(&xconf->targets.ports, range.begin, range.end);
    rangelist_sort(&xconf->targets.ports);
    xconf->scan_type.ping = 1;

    return CONF_OK;
}

static int SET_arpscan(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->scan_type.arp || xconf->echo_all)
            fprintf(xconf->echo, "arpscan = %s\n", xconf->scan_type.arp?"true":"false");
        return 0;
    }

    struct Range range;

    if (parseBoolean(value)) {
        range.begin = Templ_ARP;
        range.end = Templ_ARP;
        rangelist_add_range(&xconf->targets.ports, range.begin, range.end);
        rangelist_sort(&xconf->targets.ports);
        xconf_set_parameter(xconf, "router-mac", "ff-ff-ff-ff-ff-ff");
        xconf->scan_type.arp = 1;
    }

    return CONF_OK;
}

static int SET_banners(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->is_banners || xconf->echo_all)
            fprintf(xconf->echo, "banners = %s\n", xconf->is_banners?"true":"false");
       return 0;
    }
    xconf->is_banners = parseBoolean(value);

    if (xconf->is_banners && xconf->is_stateless_banners) {
        fprintf(stderr, "FAIL %s: can not specify banners mode and stateless-banners mode at the same time.\n", name);
        fprintf(stderr, "Hint: banners mode gets banners with TCP\\IP stack in user mode.\n");
        fprintf(stderr, "Hint: stateless-banners mode gets banners in stateless. \n");
        return CONF_ERR;
    }

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

static int SET_feed_lzr(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->output.is_feed_lzr || xconf->echo_all)
            fprintf(xconf->echo, "feed-lzr = %s\n", xconf->output.is_feed_lzr?"true":"false");
       return 0;
    }
    xconf->output.is_feed_lzr = parseBoolean(value);
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

static int SET_conn_timeout(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->tcp_connection_timeout || xconf->echo_all)
            fprintf(xconf->echo, "connection-timeout = %u\n",
                xconf->tcp_connection_timeout);
       return 0;
    }

    xconf->tcp_connection_timeout = parseInt(value);

    return CONF_OK;
}

static int SET_banners_rawudp(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->is_banners_rawudp || xconf->echo_all)
            fprintf(xconf->echo, "rawudp = %s\n", xconf->is_banners_rawudp?"true":"false");
       return 0;
    }
    xconf->is_banners_rawudp = parseBoolean(value);
    if (xconf->is_banners_rawudp)
        xconf->is_banners = true;

    if (xconf->is_banners && xconf->is_stateless_banners) {
        fprintf(stderr, "FAIL %s: can not specify banners mode and stateless-banners mode at the same time.\n", name);
        fprintf(stderr, "Hint: banners mode gets banners with TCP\\IP stack in user mode.\n");
        fprintf(stderr, "Hint: stateless-banners mode gets banners in stateless. \n");
        return CONF_ERR;
    }

    return CONF_OK;
}

static int SET_capture(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (!xconf->is_capture_cert || xconf->echo_all)
            fprintf(xconf->echo, "%scapture = cert\n", xconf->is_capture_cert?"":"no");
        if (!xconf->is_capture_servername || xconf->echo_all)
            fprintf(xconf->echo, "%scapture = servername\n", xconf->is_capture_servername?"":"no");
        if (xconf->is_capture_html || xconf->echo_all)
            fprintf(xconf->echo, "%scapture = html\n", xconf->is_capture_html?"":"no");
        if (xconf->is_capture_heartbleed || xconf->echo_all)
            fprintf(xconf->echo, "%scapture = heartbleed\n", xconf->is_capture_heartbleed?"":"no");
        if (xconf->is_capture_ticketbleed || xconf->echo_all)
            fprintf(xconf->echo, "%scapture = ticketbleed\n", xconf->is_capture_ticketbleed?"":"no");
        if (xconf->is_capture_stateless || xconf->echo_all)
            fprintf(xconf->echo, "%scapture = stateless\n", xconf->is_capture_stateless?"":"no");
        return 0;
    }
    if (EQUALS("capture", name)) {
        if (EQUALS("cert", value))
            xconf->is_capture_cert = 1;
        else if (EQUALS("servername", value))
            xconf->is_capture_servername = 1;
        else if (EQUALS("html", value))
            xconf->is_capture_html = 1;
        else if (EQUALS("heartbleed", value))
            xconf->is_capture_heartbleed = 1;
        else if (EQUALS("ticketbleed", value))
            xconf->is_capture_ticketbleed = 1;
        else if (EQUALS("stateless", value))
            xconf->is_capture_stateless = 1;
        else {
            fprintf(stderr, "FAIL: %s: unknown capture type\n", value);
            return CONF_ERR;
        }
    } else if (EQUALS("nocapture", name)) {
        if (EQUALS("cert", value))
            xconf->is_capture_cert = 0;
        else if (EQUALS("servername", value))
            xconf->is_capture_servername = 0;
        else if (EQUALS("html", value))
            xconf->is_capture_html = 0;
        else if (EQUALS("heartbleed", value))
            xconf->is_capture_heartbleed = 0;
        else if (EQUALS("ticketbleed", value))
            xconf->is_capture_ticketbleed = 0;
        else if (EQUALS("stateless", value))
            xconf->is_capture_stateless = 0;
        else {
            fprintf(stderr, "FAIL: %s: unknown nocapture type\n", value);
            return CONF_ERR;
        }
    }
    return CONF_OK;
}

static int SET_banner_type(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->banner_types.count > 0) {
            fprintf(xconf->echo, "banner types =");
            /*Actually, only one type will be print*/
            for (unsigned i=0; i<xconf->banner_types.count; i++) {
                fprintf(xconf->echo, " %s",
                    masscan_app_to_string(xconf->banner_types.list[i].begin));
            }
            fprintf(xconf->echo, "\n");
        }
        return 0;
    }

    /*It may only add one type*/
    enum ApplicationProtocol app;
    app = masscan_string_to_app(value);
    
    if (app) {
        rangelist_add_range(&xconf->banner_types, app, app);
        rangelist_sort(&xconf->banner_types);
    } else {
        fprintf(stderr, "FAIL: bad banner app: %s\n", value);
        return CONF_ERR;
    }

    return CONF_OK;
}

static int SET_hello(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->is_hello_ssl) {
            fprintf(xconf->echo, "hello = ssl\n");
        } else if (xconf->is_hello_smbv1) {
            fprintf(xconf->echo, "hello = smbv1\n");
        } else if (xconf->is_hello_http) {
            fprintf(xconf->echo, "hello = http\n");
        }
        return 0;
    }
    if (EQUALS("ssl", value))
        xconf->is_hello_ssl = 1;
    else if (EQUALS("smbv1", value))
        xconf->is_hello_smbv1 = 1;
    else if (EQUALS("http", value))
        xconf->is_hello_http = 1;
    else {
        fprintf(stderr, "FAIL: %s: unknown hello type\n", value);
        return CONF_ERR;
    }
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

    if (name[0]=='t') {
        xconf->scan_type.tcp = 1;
        rangelist_parse_ports(&xconf->targets.ports, value, &is_error, Templ_TCP);
    } else if (name[0]=='u') {
        xconf->scan_type.udp = 1;
        rangelist_parse_ports(&xconf->targets.ports, value, &is_error, Templ_UDP);
    } else {
        unsigned defaultrange = 0;

        if (xconf->scan_type.udp)
            defaultrange = Templ_UDP;
        else if (xconf->scan_type.sctp)
            defaultrange = Templ_SCTP;
        
        err = massip_add_port_string(&xconf->targets, value, defaultrange);
    }

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

    if (xconf->scan_type.udp)
        defaultrange = Templ_UDP;
    else if (xconf->scan_type.sctp)
        defaultrange = Templ_SCTP;
    
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

    if (EQUALS("resume", name))
        xconf->output.is_append = true;

    return CONF_OK;
}

static int SET_hello_file(struct Xconf *xconf, const char *name, const char *value)
{
    unsigned index;
    FILE *fp;
    char buf[16384];
    char buf2[16384];
    size_t bytes_read;
    size_t bytes_encoded;
    char foo[64];

    if (xconf->echo) {
        //Echoed as a string "hello-string" that was originally read
        //from a file, not the "hello-filename"
        return 0;
    }
    
    index = ARRAY(name);
    if (index >= 65536) {
        fprintf(stderr, "%s: bad index\n", name);
        return CONF_ERR;
    }

    /* When connecting via TCP, send this file */
    fp = fopen(value, "rb");
    if (fp == NULL) {
        LOG(0, "[-] [FAILED] --hello-file\n");
        LOG(0, "[-] %s: %s\n", value, strerror(errno));
        return CONF_ERR;
    }
    
    bytes_read = fread(buf, 1, sizeof(buf), fp);
    if (bytes_read == 0) {
        LOG(0, "[FAILED] could not read hello file\n");
        perror(value);
        fclose(fp);
        return CONF_ERR;
    }
    fclose(fp);
    
    bytes_encoded = base64_encode(buf2, sizeof(buf2)-1, buf, bytes_read);
    buf2[bytes_encoded] = '\0';
    
    snprintf(foo, sizeof(foo), "hello-string[%u]", (unsigned)index);
    
    xconf_set_parameter(xconf, foo, buf2);

    return CONF_OK;
}

static int SET_hello_string(struct Xconf *xconf, const char *name, const char *value)
{
    unsigned index;
    char *value2;
    struct TcpCfgPayloads *pay;

    if (xconf->echo) {
        for (pay = xconf->payloads.tcp; pay; pay = pay->next) {
            fprintf(xconf->echo, "hello-string[%u] = %s\n",
                    pay->port, pay->payload_base64);
        }
        return 0;
    }
    
    index = ARRAY(name);
    if (index >= 65536) {
        fprintf(stderr, "%s: bad index\n", name);
        exit(1);
    }

    
    value2 = STRDUP(value);

    pay = MALLOC(sizeof(*pay));
    
    pay->payload_base64 = value2;
    pay->port = index;
    pay->next = xconf->payloads.tcp;
    xconf->payloads.tcp = pay;
    return CONF_OK;
}

static int SET_hello_timeout(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->tcp_hello_timeout || xconf->echo_all)
            fprintf(xconf->echo, "hello-timeout = %u\n", xconf->tcp_hello_timeout);
        return 0;
    }
    xconf->tcp_hello_timeout = (unsigned)parseInt(value);
    return CONF_OK;
}

static int SET_http_cookie(struct Xconf *xconf, const char *name, const char *value)
{
    unsigned char *newvalue;
    size_t value_length;

    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->http.cookies_count || xconf->echo_all) {
            size_t i;
            for (i=0; i<xconf->http.cookies_count; i++) {
                fprintf(xconf->echo,
                        "http-cookie = %.*s\n",
                        (unsigned)xconf->http.cookies[i].value_length,
                        xconf->http.cookies[i].value);
            }
        }
        return 0;
    }

    /* allocate new value */
    value_length = strlen(value);
    newvalue = MALLOC(value_length+1);
    memcpy(newvalue, value, value_length+1);
    newvalue[value_length] = '\0';

    /* Add to our list of headers */
    if (xconf->http.cookies_count < sizeof(xconf->http.cookies)/sizeof(xconf->http.cookies[0])) {
        size_t x = xconf->http.cookies_count;
        xconf->http.cookies[x].value = newvalue;
        xconf->http.cookies[x].value_length = value_length;
        xconf->http.cookies_count++;
    }
    return CONF_OK;
}

static int SET_http_header(struct Xconf *xconf, const char *name, const char *value)
{
    unsigned name_length;
    char *newname;
    unsigned char *newvalue;
    size_t value_length;

    if (xconf->echo) {
        if (xconf->http.headers_count || xconf->echo_all) {
            size_t i;
            for (i=0; i<xconf->http.headers_count; i++) {
                if (xconf->http.headers[i].name == 0)
                    continue;
                fprintf(xconf->echo,
                        "http-header = %s:%.*s\n",
                        xconf->http.headers[i].name,
                        (unsigned)xconf->http.headers[i].value_length,
                        xconf->http.headers[i].value);
            }
        }
        return 0;
    }

    /* 
     * allocate a new name 
     */
    name += 11;
    if (*name == '[') {
        /* Specified as: "--http-header[name] value" */
        while (ispunct(*name))
            name++;
        name_length = (unsigned)strlen(name);
        while (name_length && ispunct(name[name_length-1]))
            name_length--;
        newname = MALLOC(name_length+1);
        memcpy(newname, name, name_length+1);
        newname[name_length] = '\0';
    } else if (strchr(value, ':')) {
        /* Specified as: "--http-header Name:value" */
        name_length = INDEX_OF(value, ':');
        newname = MALLOC(name_length + 1);
        memcpy(newname, value, name_length + 1);
            
        /* Trim the value */
        value = value + name_length + 1;
        while (*value && isspace(*value & 0xFF))
            value++;

        /* Trim the name */
        while (name_length && isspace(newname[name_length-1]&0xFF))
            name_length--;
        newname[name_length] = '\0';
    } else {
        fprintf(stderr, "[-] --http-header needs both a name and value\n");
        fprintf(stderr, "    hint: \"--http-header Name:value\"\n");
        exit(1);
    }

    /* allocate new value */
    value_length = strlen(value);
    newvalue = MALLOC(value_length+1);
    memcpy(newvalue, value, value_length+1);
    newvalue[value_length] = '\0';

    /* Add to our list of headers */
    if (xconf->http.headers_count < sizeof(xconf->http.headers)/sizeof(xconf->http.headers[0])) {
        size_t x = xconf->http.headers_count;
        xconf->http.headers[x].name = newname;
        xconf->http.headers[x].value = newvalue;
        xconf->http.headers[x].value_length = value_length;
        xconf->http.headers_count++;
    }
    return CONF_OK;
}

static int SET_http_method(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->http.method || xconf->echo_all)
            fprintf(xconf->echo, "http-method = %.*s\n", (unsigned)xconf->http.method_length, xconf->http.method);
        return 0;
    }
    if (xconf->http.method)
        free(xconf->http.method);
    xconf->http.method_length = strlen(value);
    xconf->http.method = MALLOC(xconf->http.method_length+1);
    memcpy(xconf->http.method, value, xconf->http.method_length+1);
    return CONF_OK;
}
static int SET_http_url(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->http.url || xconf->echo_all)
            fprintf(xconf->echo, "http-url = %.*s\n", (unsigned)xconf->http.url_length, xconf->http.url);
        return 0;
    }
    if (xconf->http.url)
        free(xconf->http.url);
    xconf->http.url_length = strlen(value);
    xconf->http.url = MALLOC(xconf->http.url_length+1);
    memcpy(xconf->http.url, value, xconf->http.url_length+1);
    return CONF_OK;
}
static int SET_http_version(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->http.version || xconf->echo_all)
            fprintf(xconf->echo, "http-version = %.*s\n", (unsigned)xconf->http.version_length, xconf->http.version);
        return 0;
    }
    if (xconf->http.version)
        free(xconf->http.version);
    xconf->http.version_length = strlen(value);
    xconf->http.version = MALLOC(xconf->http.version_length+1);
    memcpy(xconf->http.version, value, xconf->http.version_length+1);
    return CONF_OK;
}
static int SET_http_host(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->http.host || xconf->echo_all)
            fprintf(xconf->echo, "http-host = %.*s\n", (unsigned)xconf->http.host_length, xconf->http.host);
        return 0;
    }
    if (xconf->http.host)
        free(xconf->http.host);
    xconf->http.host_length = strlen(value);
    xconf->http.host = MALLOC(xconf->http.host_length+1);
    memcpy(xconf->http.host, value, xconf->http.host_length+1);
    return CONF_OK;
}

static int SET_http_user_agent(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->http.user_agent || xconf->echo_all)
            fprintf(xconf->echo, "http-user-agent = %.*s\n", (unsigned)xconf->http.user_agent_length, xconf->http.user_agent);
        return 0;
    }
    if (xconf->http.user_agent)
        free(xconf->http.user_agent);
    xconf->http.user_agent_length = strlen(value);
    xconf->http.user_agent = MALLOC(xconf->http.user_agent_length+1);
    memcpy( xconf->http.user_agent,
            value,
            xconf->http.user_agent_length+1
            );
    return CONF_OK;
}

static int SET_http_payload(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->http.payload || xconf->echo_all)
            fprintf(xconf->echo, "http-payload = %.*s\n", (unsigned)xconf->http.payload_length, xconf->http.payload);
        return 0;
    }
    xconf->http.payload_length = strlen(value);
    xconf->http.payload = REALLOC(xconf->http.payload, xconf->http.payload_length+1);
    memcpy( xconf->http.payload,
            value,
            xconf->http.payload_length+1
            );
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

static int SET_json_status(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->output.is_status_ndjson || xconf->echo_all)
            fprintf(xconf->echo, "ndjson-status = %s\n", xconf->output.is_status_ndjson?"true":"false");
        return 0;
    }
    xconf->output.is_status_ndjson = parseBoolean(value);
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


static int SET_nobanners(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        return 0;
    }
    xconf->is_banners = !parseBoolean(value);
    return CONF_OK;
}

static int SET_noreset(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->is_noreset1 || xconf->echo_all)
            fprintf(xconf->echo, "noreset1 = %s\n", xconf->is_noreset1?"true":"false");
        if (xconf->is_noreset2 || xconf->echo_all)
            fprintf(xconf->echo, "noreset2 = %s\n", xconf->is_noreset2?"true":"false");
        return 0;
    }

    if (EQUALS(name, "noreset1"))
        xconf->is_noreset1 = parseBoolean(value);
    else if (EQUALS(name, "noreset2"))
        xconf->is_noreset2 = parseBoolean(value);
    else if (EQUALS(name, "noreset")) {
        xconf->is_noreset1 = parseBoolean(value);
        xconf->is_noreset2 = parseBoolean(value);
    }

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

static int SET_output_append(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->output.is_append || xconf->echo_all)
            fprintf(xconf->echo, "output-append = %s\n",
                    xconf->output.is_append?"true":"false");
        return 0;
    }
    if (EQUALS("overwrite", name) || !parseBoolean(value))
        xconf->output.is_append = 0;
    else
        xconf->output.is_append = 1;
    return CONF_OK;
}

static int SET_output_filename(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->output.filename[0] || xconf->echo_all)
            fprintf(xconf->echo, "output-filename = %s\n", xconf->output.filename);
        return 0;
    }
    if (xconf->output.format == 0)
        xconf->output.format = Output_XML; /*TODO: Why is the default XML?*/
    safe_strcpy(xconf->output.filename,
             sizeof(xconf->output.filename),
             value);
    return CONF_OK;
}

static int SET_output_format(struct Xconf *xconf, const char *name, const char *value)
{
    enum OutputFormat x = 0;
    // UNUSEDPARM(name);
    if (xconf->echo) {
        FILE *fp = xconf->echo;
        ipaddress_formatted_t fmt;
        switch (xconf->output.format) {
            case Output_Default:    if (xconf->echo_all) fprintf(fp, "output-format = interactive\n"); break;
            case Output_Interactive:fprintf(fp, "output-format = interactive\n"); break;
            case Output_List:       fprintf(fp, "output-format = list\n"); break;
            case Output_Unicornscan:fprintf(fp, "output-format = unicornscan\n"); break;
            case Output_XML:        fprintf(fp, "output-format = xml\n"); break;
            case Output_Binary:     fprintf(fp, "output-format = binary\n"); break;
            case Output_Grepable:   fprintf(fp, "output-format = grepable\n"); break;
            case Output_JSON:       fprintf(fp, "output-format = json\n"); break;
            case Output_NDJSON:     fprintf(fp, "output-format = ndjson\n"); break;
            case Output_Certs:      fprintf(fp, "output-format = certs\n"); break;
            case Output_None:       fprintf(fp, "output-format = none\n"); break;
            case Output_Hostonly:   fprintf(fp, "output-format = hostonly\n"); break;
            case Output_Redis:
                fmt = ipaddress_fmt(xconf->redis.ip);
                fprintf(fp, "output-format = redis\n");
                fprintf(fp, "redis = %s %u\n", fmt.string, xconf->redis.port);
                break;
                
            default:
                fprintf(fp, "output-format = unknown(%u)\n", xconf->output.format);
                break;
        }
        return 0;
    }

    if (EQUALS("unknown(0)", value))                            x = Output_Interactive;
    else if (EQUALS("interactive", value))                      x = Output_Interactive;
    else if (EQUALS("list", value)||EQUALS("oL", name))         x = Output_List;
    else if (EQUALS("unicornscan", value)||EQUALS("oU", name))  x = Output_Unicornscan;
    else if (EQUALS("xml", value)||EQUALS("oX", name))          x = Output_XML;
    else if (EQUALS("binary", value)||EQUALS("oB", name))       x = Output_Binary;
    else if (EQUALS("greppable", value)||EQUALS("oG", name))    x = Output_Grepable;
    else if (EQUALS("grepable", value)||EQUALS("oG", name))     x = Output_Grepable;
    else if (EQUALS("json", value)||EQUALS("oJ", name))         x = Output_JSON;
    else if (EQUALS("ndjson", value)||EQUALS("oD", name))       x = Output_NDJSON;
    else if (EQUALS("certs", value))                            x = Output_Certs;
    else if (EQUALS("none", value))                             x = Output_None;
    else if (EQUALS("redis", value)||EQUALS("oR", name))        x = Output_Redis;
    else if (EQUALS("hostonly", value)||EQUALS("oH", name))     x = Output_Hostonly;
    else {
        fprintf(stderr, "FAIL: unknown output-format: %s\n", value);
        fprintf(stderr, "  hint: 'binary', 'xml', 'grepable', ...\n");
        return CONF_ERR;
    }
    xconf->output.format = x;

    return CONF_OK;
}

static int SET_output_noshow(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->echo_all) {
            fprintf(xconf->echo, "output-noshow = %s%s%s\n",
                    (!xconf->output.is_show_open)?"open,":"",
                    (!xconf->output.is_show_closed)?"closed,":"",
                    (!xconf->output.is_show_host)?"host,":""
                    );
        }
        return 0;
    }
    for (;;) {
        const char *val2 = value;
        unsigned val2_len = INDEX_OF(val2, ',');
        if (val2_len == 0)
            break;
        if (EQUALSx("open", val2, val2_len))
            xconf->output.is_show_open = 0;
        else if (EQUALSx("closed", val2, val2_len) || EQUALSx("close", val2, val2_len))
            xconf->output.is_show_closed = 0;
        else if (EQUALSx("open", val2, val2_len))
            xconf->output.is_show_host = 0;
        else if (EQUALSx("all",val2,val2_len)) {
            xconf->output.is_show_open = 0;
            xconf->output.is_show_host = 0;
            xconf->output.is_show_closed = 0;
        }
        else {
            LOG(0, "FAIL: unknown 'noshow' spec: %.*s\n", val2_len, val2);
            exit(1);
        }
        value += val2_len;
        while (*value == ',')
            value++;
    }
    return CONF_OK;
}

static int SET_output_show(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->echo_all) {
            fprintf(xconf->echo, "output-show = %s%s%s\n",
                    xconf->output.is_show_open?"open,":"",
                    xconf->output.is_show_closed?"closed,":"",
                    xconf->output.is_show_host?"host,":""
                    );
        }
        return 0;
    }
    for (;;) {
        const char *val2 = value;
        unsigned val2_len = INDEX_OF(val2, ',');
        if (val2_len == 0)
            break;
        if (EQUALSx("open", val2, val2_len))
            xconf->output.is_show_open = 1;
        else if (EQUALSx("closed", val2, val2_len) || EQUALSx("close", val2, val2_len))
            xconf->output.is_show_closed = 1;
        else if (EQUALSx("open", val2, val2_len))
            xconf->output.is_show_host = 1;
        else if (EQUALSx("all",val2,val2_len)) {
            xconf->output.is_show_open = 1;
            xconf->output.is_show_host = 1;
            xconf->output.is_show_closed = 1;
        }
        else {
            LOG(0, "FAIL: unknown 'show' spec: %.*s\n", val2_len, val2);
            exit(1);
        }
        value += val2_len;
        while (*value == ',')
            value++;
    }
    return CONF_OK;
}

static int SET_output_redis(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->output.format==Output_Redis || xconf->echo_all) {
            fprintf(xconf->echo, "redis address = %s:%u\n",
                ipv4address_fmt((ipv4address)(xconf->redis.ip.ipv4)).string,
                xconf->redis.port);
        }
        return 0;
    }

    struct Range range;
    unsigned offset = 0;
    unsigned max_offset = (unsigned)strlen(value);
    unsigned port = 6379;

    range = range_parse_ipv4(value, &offset, max_offset);
    if ((range.begin == 0 && range.end == 0) || range.begin != range.end) {
        fprintf(stderr, "FAIL:  bad redis IP address: %s\n", value);
        return CONF_ERR;
    }
    if (offset < max_offset) {
        while (offset < max_offset && isspace(value[offset]))
            offset++;
        if (offset+1 < max_offset && value[offset] == ':' && isdigit(value[offset+1]&0xFF)) {
            port = (unsigned)strtoul(value+offset+1, 0, 0);
            if (port > 65535 || port == 0) {
                fprintf(stderr, "FAIL: bad redis port: %s\n", value+offset+1);
                return CONF_ERR;
            }
        }
    }

    /* TODO: add support for connecting to IPv6 addresses here */
    xconf->redis.ip.ipv4 = range.begin;
    xconf->redis.ip.version = 4;

    xconf->redis.port = port;
    xconf->output.format = Output_Redis;
    safe_strcpy(xconf->output.filename, 
                sizeof(xconf->output.filename), 
                "<redis>");

    return CONF_OK;
}

static int SET_redis_password(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->redis.password[0] || xconf->echo_all)
            fprintf(xconf->echo, "redis-password = %s\n",
                xconf->redis.password);
        return 0;
    }
    safe_strcpy(xconf->redis.password, 20, value);
    return CONF_OK;
}

static int SET_reason(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->output.is_reason || xconf->echo_all)
            fprintf(xconf->echo, "show reason = %s\n",
                xconf->output.is_reason?"true":"false");
        return 0;
    }
    xconf->output.is_reason =  parseBoolean(value);
    return CONF_OK;
}

static int SET_output_show_open(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }
    /* "open" "open-only" */
    xconf->output.is_show_open = 1;
    xconf->output.is_show_closed = 0;
    xconf->output.is_show_host = 0;
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

static int SET_status(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (!xconf->output.is_status_updates || xconf->echo_all)
            fprintf(xconf->echo, "update status = %s\n",
                xconf->output.is_status_updates?"true":"false");
        return 0;
    }
    
    if (EQUALS("status", name))
        xconf->output.is_status_updates = parseBoolean(value);
    else if (EQUALS("nostatus", name))
        xconf->output.is_status_updates = !parseBoolean(value);
    
    return CONF_OK;
}

static int SET_interactive(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->output.is_interactive || xconf->echo_all)
            fprintf(xconf->echo, "output interacitve = %s\n",
                xconf->output.is_interactive?"true":"false");
        return 0;
    }
    
    if (EQUALS("interactive", name))
        xconf->output.is_interactive = parseBoolean(value);
    else if (EQUALS("nointeractive", name))
        xconf->output.is_interactive = !parseBoolean(value);
    
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

static int SET_retries(struct Xconf *xconf, const char *name, const char *value)
{
    uint64_t x;
    
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->retries || xconf->echo_all)
            fprintf(xconf->echo, "retries = %u\n", xconf->retries);
        return 0;
    }
    x = strtoul(value, 0, 0);
    if (x >= 1000) {
        fprintf(stderr, "FAIL: retries=<n>: expected number less than 1000\n");
        return CONF_ERR;
    }
    xconf->retries = (unsigned)x;
    return CONF_OK;
    
}

static int SET_rotate_time(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->output.rotate.timeout || xconf->echo_all)
            fprintf(xconf->echo, "rotate = %u\n", xconf->output.rotate.timeout);
        return 0;
    }
    xconf->output.rotate.timeout = (unsigned)parseTime(value);
    return CONF_OK;
}
static int SET_rotate_directory(struct Xconf *xconf, const char *name, const char *value)
{
    char *p;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (memcmp(xconf->output.rotate.directory, ".",2) != 0 || xconf->echo_all) {
            fprintf(xconf->echo, "rotate-dir = %s\n", xconf->output.rotate.directory);
        }
        return 0;
    }
    safe_strcpy(   xconf->output.rotate.directory,
             sizeof(xconf->output.rotate.directory),
             value);
    /* strip trailing slashes */
    p = xconf->output.rotate.directory;
    while (*p && (p[strlen(p)-1] == '/' || p[strlen(p)-1] == '\\')) /* Fix for #561 */
        p[strlen(p)-1] = '\0';
    return CONF_OK;
}
static int SET_rotate_offset(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    /* Time offset, otherwise output files are aligned to nearest time
     * interval, e.g. at the start of the hour for "hourly" */
    if (xconf->echo) {
        if (xconf->output.rotate.offset || xconf->echo_all)
            fprintf(xconf->echo, "rotate-offset = %u\n", xconf->output.rotate.offset);
        return 0;
    }
    xconf->output.rotate.offset = (unsigned)parseTime(value);
    return CONF_OK;
}
static int SET_rotate_filesize(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->output.rotate.filesize || xconf->echo_all)
            fprintf(xconf->echo, "rotate-size = %" PRIu64 "\n", xconf->output.rotate.filesize);
        return 0;
    }
    xconf->output.rotate.filesize = parseSize(value);
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

static int SET_script(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if ((xconf->scripting.name && xconf->scripting.name[0]) || xconf->echo_all)
            fprintf(xconf->echo, "script = %s\n", xconf->scripting.name);
        return 0;
    }
    if (value && value[0])
        xconf->is_scripting = 1;
    else
        xconf->is_scripting = 0;
    
    if (xconf->scripting.name)
        free(xconf->scripting.name);
    
    xconf->scripting.name = strdup(value);
    
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

static int SET_banner1(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }
    banner1_test(value);
    return CONF_ERR;
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

static int SET_vuln_check(struct Xconf *xconf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->is_heartbleed || xconf->echo_all)
            fprintf(xconf->echo, "vulncheck heartbleed = %s\n",
                xconf->is_heartbleed?"true":"false");
        if (xconf->is_ticketbleed || xconf->echo_all)
            fprintf(xconf->echo, "vulncheck ticketbleed = %s\n",
                xconf->is_ticketbleed?"true":"false");
        if (xconf->is_poodle_sslv3 || xconf->echo_all)
            fprintf(xconf->echo, "vulncheck poodle-sslv3 = %s\n",
                xconf->is_poodle_sslv3?"true":"false");
        return 0;
    }

    if (EQUALS("heartbleed", value)) {
        xconf->is_heartbleed = 1;
        xconf_set_parameter(xconf, "no-capture", "cert");
        xconf_set_parameter(xconf, "no-capture", "heartbleed");
        xconf_set_parameter(xconf, "banners", "true");
    } else if (EQUALS("ticketbleed", value)) {
        xconf->is_ticketbleed = 1;
        xconf_set_parameter(xconf, "no-capture", "cert");
        xconf_set_parameter(xconf, "no-capture", "ticketbleed");
        xconf_set_parameter(xconf, "banners", "true");
    } else if (EQUALS("poodle", value) || EQUALS("sslv3", value)) {
        xconf->is_poodle_sslv3 = 1;
        xconf_set_parameter(xconf, "no-capture", "cert");
        xconf_set_parameter(xconf, "banners", "true");
    } else {
        if (!vulncheck_lookup(value)) {
            fprintf(stderr, "FAIL: vuln check '%s' does not exist\n", value);
            fprintf(stderr, "  hint: use '--vuln list' to list available scripts\n");
            return CONF_ERR;
        }
        if (xconf->vuln_name != NULL) {
            if (strcmp(xconf->vuln_name, value) != 0) {
                fprintf(stderr, "FAIL: only one vuln check supported at a time\n");
                fprintf(stderr, "  hint: '%s' is existing vuln check, '%s' is new vuln check\n",
                        xconf->vuln_name, value);
                return CONF_ERR;
            }
        }
        xconf->vuln_name = vulncheck_lookup(value)->name;
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
    printf("usage: "XTATE_NAME" [options] [<IP|RANGE>... -p PORT[,PORT...]]\n");
    printf("\n");
    printf("original examples in xtate:\n");
    printf("    "XTATE_NAME" -p 80,8000-8100 10.0.0.0/8 --rate=10000\n");
    printf("        scan some web ports on 10.x.x.x at 10kpps\n");
    printf("\n");
    printf("    "XTATE_NAME" -p 80 10.0.0.0/8 --banners -oB <filename>\n");
    printf("        save results of scan in binary format to <filename>\n");
    printf("\n");
    printf("    "XTATE_NAME" --open --banners --readscan <filename> -oX <savefile>\n");
    printf("        read binary scan results in <filename> and save them as xml in <savefile>\n");
    printf("\n");
    printf("    "XTATE_NAME" 10.0.0.0/8 -p 21,110 --stateless\n");
    printf("        scan some ftp & pop3 ports with default NULL probe\n");
    printf("\n");
    printf("    "XTATE_NAME" 10.0.0.0/8 -p 80 --stateless --probe getrequest\n");
    printf("        scan some web ports with GetRequest probe\n");
    printf("\n");
    printf("    "XTATE_NAME" 10.0.0.0/8 -p 110 --stateless --capture stateless\n");
    printf("        capture banner result\n");
    printf("\n");
    printf("    "XTATE_NAME" 10.0.0.0/8 -p 110 --stateless --pcap <pcapfile> -oX <xmlfile>\n");
    printf("        save packet result in <pcapfile> and save scan result in <xmlfile>\n");
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

static int SET_output_stylesheet(struct Xconf *xconf, const char *name, const char *value)
{
    if (xconf->echo) {
        if (xconf->output.stylesheet[0] || xconf->echo_all)
            fprintf(xconf->echo, "stylesheet = %s\n", xconf->output.stylesheet);
        return 0;
    }


    if (name[0]=='n') {
        xconf->output.stylesheet[0] = '\0';
        return CONF_OK;
    }
    
    if (xconf->output.format == 0)
        xconf->output.format = Output_XML;

    const char webxml[] =  "http://nmap.org/svn/docs/nmap.xsl";
    if (EQUALS(name, "webxml"))
        safe_strcpy(xconf->output.stylesheet, sizeof(xconf->output.stylesheet), webxml);
    else
        safe_strcpy(xconf->output.stylesheet, sizeof(xconf->output.stylesheet), value);
    return CONF_OK;
}

static int SET_top_port(struct Xconf *xconf, const char *name, const char *value)
{
    unsigned default_value = 20;

    if (xconf->echo) {
        /* don't echo: this instead triggers filling the `--port`
         * list, so the ports themselves will be echoed, not this
         * parameter */
        return 0;
    }

    if (value == 0 || value[0] == '\0') {
        /* can be specified by itself on the command-line, alone
         * without a following parameter */
        /* ex: `--top-ports` */
        xconf->top_ports = default_value;
    } else if (isBoolean(value)) {
        /* ex: `--top-ports enable` */
        if (parseBoolean(value))
            xconf->top_ports = default_value;
        else
            xconf->top_ports = 0;
    } else if (isInteger(value)) {
        /* ex: `--top-ports 5` */
        uint64_t num = parseInt(value);
        xconf->top_ports = (unsigned)num;
    } else {
        fprintf(stderr, "[-] %s: bad value: %s\n", name, value);
        return CONF_ERR;
    }
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

static int SET_debug_tcp(struct Xconf *xconf, const char *name, const char *value)
{
    extern int is_tcp_debug; /* global */

    UNUSEDPARM(name);
    UNUSEDPARM(xconf);

    if (xconf->echo) {
        if (is_tcp_debug || xconf->echo_all)
            fprintf(xconf->echo, "tcp debug = %s\n", is_tcp_debug?"true":"false");
        return 0;
    }

    if (value == 0 || value[0] == '\0')
        is_tcp_debug = 1;
    else
        is_tcp_debug = parseBoolean(value);
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
    {"top-port",        SET_top_port,           F_NUMABLE, {"top-ports",0}},
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

    {"OPERATION:",      SET_delimiter,          0,      {0}},

    {"echo",            SET_echo,               F_BOOL, {"echo-all", "echo-cidr",0}},
    {"iflist",          SET_iflist,             F_BOOL, {"list-interface", "list-adapter",0}},
    {"readrange",       SET_read_range,         F_BOOL, {"readranges", 0}},
    {"readscan",        SET_read_scan,          F_BOOL, {0}},
    {"listtarget",      SET_list_target,        F_BOOL, {"list-targets",0}},
    {"selftest",        SET_selftest,           F_BOOL, {"regress", "regression",0}},
    {"benchmark",       SET_benchmark,          F_BOOL, {0}},
    {"debug-if",        SET_debug_interface,    F_BOOL, {"debug-interface",0}},

    {"SCAN TYPE:",      SET_delimiter,          0,      {0}},

    {"arpscan",         SET_arpscan,            F_BOOL, {"arp",0}},
    {"ping",            SET_ping,               F_BOOL, {0}},
    {"oproto",          SET_oproto,             F_BOOL, {"oprotos",0}}, /*other IP protocol*/

    {"STATUS & OUTPUT & RESULT:",SET_delimiter, 0,      {0}},

    {"interactive",     SET_interactive,        F_BOOL, {"nointeractive",0}},
    {"status",          SET_status,             F_BOOL, {"nostatus",0}},
    {"json-status",     SET_json_status,        F_BOOL, {"status-json", 0}},

    {"output-filename", SET_output_filename,    0,      {"output-file",0}},
    {"output-format",   SET_output_format,      0,      {0}},
    {"oB",              SET_output_format,      F_BOOL, {"oD","oJ","oX","oR","oG",0}},
    {"oL",              SET_output_format,      F_BOOL, {"oU","oH",0}},
    {"output-show",     SET_output_show,        0,      {"output-status", "show",0}},
    {"output-noshow",   SET_output_noshow,      0,      {"noshow",0}},
    {"output-show-open",SET_output_show_open,   F_BOOL, {"open", "open-only", 0}},
    {"output-append",   SET_output_append,      0,      {"append-output",0}},
    {"output-redis",    SET_output_redis,       0,      {"redis",0}}, /*--redis IP:port*/
    {"redis-password",  SET_redis_password,     0,      {"redis-pwd",0}},
    {"reason",          SET_reason,             F_BOOL, {0}},

    {"rotate",          SET_rotate_time,        0,      {"output-rotate", "rotate-output", "rotate-time", 0}},
    {"rotate-dir",      SET_rotate_directory,   0,      {"output-rotate-dir", "rotate-directory", 0}},
    {"rotate-offset",   SET_rotate_offset,      0,      {"output-rotate-offset", 0}},
    {"rotate-size",     SET_rotate_filesize,    0,      {"output-rotate-filesize", "rotate-filesize", 0}},

    {"stylesheet",      SET_output_stylesheet,  0,      {"webxml", "no-stylesheet",0}},
    {"feed-lzr",        SET_feed_lzr,           F_BOOL, {"feedlzr", 0}},

    {"pcap-filename",   SET_pcap_filename,      0,      {"pcap",0}},

    {"BANNERS:",        SET_delimiter,          0,      {0}},

    {"banners",         SET_banners,            F_BOOL, {"banner",0}},
    {"nobanners",       SET_nobanners,          F_BOOL, {"nobanner",0}},
    {"banner1",         SET_banner1,            F_BOOL, {0}},
    {"banner-type",     SET_banner_type,        0,      {"banner-types", "banner-app", "banner-apps",0}},
    {"rawudp",          SET_banners_rawudp,     F_BOOL, {"rawudp",0}},
    {"conn-timeout",    SET_conn_timeout,       F_NUMABLE, {"connection-timeout", "tcp-timeout",0}},
    {"vuln-check",      SET_vuln_check,         0,      {"vuln",0}}, /*some fish will drop the fxck code*/

    {"BANNERS-HELLO:",  SET_delimiter,          0,      {0}},

    {"hello",           SET_hello,              0,      {0}},
    {"hello-file",      SET_hello_file,         0,      {"hello-filename",0}},
    {"hello-string",    SET_hello_string,       0,      {0}},
    {"hello-timeout",   SET_hello_timeout,      0,      {0}},

    {"BANNERS-PAYLOAD:",SET_delimiter,          0,      {0}},

    {"nmap-datadir",    SET_nmap_datadir,       0,      {"datadir",0}},
    {"nmap-datalength", SET_nmap_data_length,   F_NUMABLE,{"datalength",0}},
    {"nmap-payloads",   SET_nmap_payloads,      0,      {"nmap-payload",0}},
    {"nmap-service-probes",SET_nmap_service_probes, 0,  {"nmap-service-probe",0}},
    {"pcap-payloads",   SET_pcap_payloads,      0,      {"pcap-payload",0}},

    {"BANNERS-HTTP:",   SET_delimiter,          0,      {0}},

    {"http-cookie",     SET_http_cookie,        0,      {0}},
    {"http-header",     SET_http_header,        0,      {"http-field", 0}},
    {"http-method",     SET_http_method,        0,      {0}},
    {"http-version",    SET_http_version,       0,      {0}},
    {"http-url",        SET_http_url,           0,      {"http-uri",0}},
    {"http-user-agent", SET_http_user_agent,    0,      {0}},
    {"http-host",       SET_http_host,          0,      {0}},
    {"http-payload",    SET_http_payload,       0,      {0}},

    {"STATELESS:",      SET_delimiter,          0,      {0}},

    {"stateless-banners",SET_stateless_banners, F_BOOL, {"stateless", "stateless-banner", "stateless-mode",0}},
    {"stateless-probe", SET_stateless_probe,    0,      {"probe", 0}},
    {"list-probes",     SET_list_probes,        F_BOOL, {"list-probe", 0}},
    {"probe-args",      SET_probe_args,         0,      {"probe-arg", 0}},
    {"capture",         SET_capture,            0,      {"nocapture",0}},
    {"noreset",         SET_noreset,            F_BOOL, {"noreset1", "noreset2", 0}},

    {"SCAN MODULES:",   SET_delimiter,          0,      {0}},

    {"scan-module",     SET_scan_module,        0,      {"scan", 0}},
    {"list-scan-modules",SET_list_scan_modules, F_BOOL, {"list-scan-module", "list-scan",0}},
    {"scan-module-args", SET_scan_module_args,  0,      {"scan-module-arg",0}},

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
    {"retries",         SET_retries,            0,      {"retry",0}},
    {"offline",         SET_offline,            F_BOOL, {"notransmit", "nosend", "dry-run", 0}},
    {"nodedup",         SET_nodedup,            F_BOOL, {0}},
    {"dedup-win",       SET_dedup_win,          F_NUMABLE, {0}},
    {"stack-buf-count", SET_stack_buf_count,    F_NUMABLE, {"queue-buf-count", "packet-buf-count", 0}},
    {"pfring",          SET_pfring,             F_BOOL, {0}},
    {"send-queue",      SET_send_queue,         F_BOOL, {"sendq", 0}},
    {"blackrock-rounds",SET_blackrock_rounds,   F_NUMABLE, {"blackrock-round",0}},
    {"script",          SET_script,             0,      {0}},
    {"debug-tcp",       SET_debug_tcp,          F_BOOL, {"tcp-debug", 0}},

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

    /*
     * If no other "scan type" found, then default to TCP
     */
    if (xconf->scan_type.udp == 0 && xconf->scan_type.sctp == 0
        && xconf->scan_type.ping == 0 && xconf->scan_type.arp == 0
        && xconf->scan_type.oproto == 0)
        xconf->scan_type.tcp = 1;
    
    /*
     * If "top-ports" specified, then add all those ports. This may be in
     * addition to any other ports
     */
    if (xconf->top_ports) {
        config_top_ports(xconf, xconf->top_ports);
    }
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


/***************************************************************************
 ***************************************************************************/
int
xconf_selftest()
{
    char test[] = " test 1 ";

    trim(test, sizeof(test));
    if (strcmp(test, "test 1") != 0) {
        goto failure;
    }


    /* */
    {
        int argc = 6;
        char *argv[] = { "foo", "bar", "-ddd", "--readscan", "xxx", "--something" };
    
        if (xconf_contains("--nothing", argc, argv))
            goto failure;

        if (!xconf_contains("--readscan", argc, argv))
            goto failure;
    }

    return 0;
failure:
    fprintf(stderr, "[+] selftest failure: config subsystem\n");
    return 1;
}


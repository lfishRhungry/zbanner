#include <ctype.h>
#include <limits.h>
#include <openssl/opensslv.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "xconf.h"
#include "version.h"
#include "smack/smack.h"
#include "nmap/nmap-service.h"

#include "templ/templ-init.h"
#include "templ/templ-opts.h"
#include "templ/templ-tcp.h"

#include "crypto/crypto-base64.h"
#include "crypto/crypto-blackrock.h"
#include "crypto/crypto-siphash24.h"
#include "crypto/crypto-lcg.h"

#include "util-scan/dedup.h"
#include "util-scan/rstfilter.h"
#include "util-data/safe-string.h"
#include "util-data/fine-malloc.h"
#include "util-data/data-chain.h"
#include "util-out/xprint.h"
#include "util-out/logger.h"
#include "util-misc/cross.h"
#include "util-misc/checksum.h"
#include "util-misc/configer.h"

#include "massip/massip.h"
#include "massip/massip-addr.h"
#include "massip/massip-addr.h"
#include "massip/massip-parse.h"
#include "massip/massip-rangesport.h"

#include "proto/proto-http-maker.h"

#include "pixie/pixie-timer.h"

#ifdef WIN32
#include <direct.h>
#define getcwd _getcwd
#else
#include <unistd.h>
#endif

#if defined(_MSC_VER)
#define strdup _strdup
#endif

extern struct ConfigParam config_parameters[];


const char ascii_xtate1[] =
" /$$   /$$ /$$$$$$$$ /$$$$$$  /$$$$$$$$ /$$$$$$$$\n"
"| $$  / $$|__  $$__//$$__  $$|__  $$__/| $$_____/\n"
"|  $$/ $$/   | $$  | $$  \\ $$   | $$   | $$      \n"
" \\  $$$$/    | $$  | $$$$$$$$   | $$   | $$$$$   \n"
"  >$$  $$    | $$  | $$__  $$   | $$   | $$__/   \n"
" /$$/\\  $$   | $$  | $$  | $$   | $$   | $$      \n"
"| $$  \\ $$   | $$  | $$  | $$   | $$   | $$$$$$$$\n"
"|__/  |__/   |__/  |__/  |__/   |__/   |________/\n"
;


const char ascii_xtate2[] =
"`YMM'   `MP'MMP\"\"MM\"\"YMM   db   MMP\"\"MM\"\"YMM `7MM\"\"\"YMM  \n"
"  VMb.  ,P  P'   MM   `7  ;MM:  P'   MM   `7   MM    `7  \n"
"   `MM.M'        MM      ,V^MM.      MM        MM   d    \n"
"     MMb         MM     ,M  `MM      MM        MMmmMM    \n"
"   ,M'`Mb.       MM     AbmmmqMA     MM        MM   Y  , \n"
"  ,P   `MM.      MM    A'     VML    MM        MM     ,M \n"
".MM:.  .:MMa.  .JMML..AMA.   .AMMA..JMML.    .JMMmmmmMMM \n"
;

const char work_flow[] =
"+--------------------------------------------------------------------------------------------------+\n"
"|                                                                                                  |\n"
"|                                                                                                  |\n"
"|                                 Tx Threads                                         Tx Threads    |\n"
"|     New Targets Generation     ------------->        ScanModule Transmit          ----------->   |\n"
"|   +-------------------------+                   +----------------------------+                   |\n"
"|   | 1.Address Randomization |  ------------->   | (ProbeModule Hello Making) |    ----------->   |\n"
"|   | 2.Scan Rate Control     |                   | (Timeout Event Creating)   |                   |\n"
"|   +-------------------------+  ------------->   +----------------------------+    ----------->   |\n"
"|                                                                                                  |\n"
"|                                                                                ^                 |\n"
"|                                                                                |                 |\n"
"|       Packets need to be send   +-----------------------+  Send in priority    |                 |\n"
"|   +---------------------------->| Pakcets Sending Queue +----------------------+                 |\n"
"|   |                             +-----------------------+                                        |\n"
"|   |                                                                                              |\n"
"|   |                                                                                              |\n"
"|   |          ScanModule Handling                                                                 |\n"
"|   |   +------------------------------+   Handle Threads   ScanModule Validation                  |\n"
"|   |   |  1.ProbeModule Validation    |   <-------------  +---------------------+                 |\n"
"|   |   |  2.ProbeModule Parsing       |                   | 1.Record            |    Rx  Thread   |\n"
"|   |   |  3.OutputModule save results |   <-------------  | 2.Deduplication     |  <-----------   |\n"
"|   |   |  4.More packets to send      |                   | 3.Timeout handling  |                 |\n"
"|   +---+    (ProbeModule Hello Making)|   <-------------  +---------------------+                 |\n"
"|       +------------------------------+                                                           |\n"
"|                                                                                                  |\n"
"+--------------------------------------------------------------------------------------------------+\n"
;

const char scan_probe_module_rela[] =
"+-----------------------------------------------------------------------+\n"
"|   Free supporting for new scan strategies and protocols through       |\n"
"|   flexible ScanModules and ProbeModules creating and combination      |\n"
"|                                                                       |\n"
"|                                                                       |\n"
"|      +--------------------+           +-------------------------+     |\n"
"|      |  Application Layer +---------->|                         |     |\n"
"|      +--------------------+           |     ProbeModules        |     |\n"
"|                                       |                         |     |\n"
"|      +--------------------+           |       e.g. HTTP         |     |\n"
"|      | Presentation Layer +---------->|            DNS          |     |\n"
"|      +--------------------+           |            Netbios      |     |\n"
"|                                       |            TLS          |     |\n"
"|      +--------------------+           |                         |     |\n"
"|      |   Session Layer    +---------->|                         |     |\n"
"|      +--------------------+           +-------------------------+     |\n"
"|                                                                       |\n"
"|      +--------------------+           +-------------------------+     |\n"
"|      |   Transport Layer  +---------->|                         |     |\n"
"|      +--------------------+           |      ScanModules        |     |\n"
"|                                       |                         |     |\n"
"|      +--------------------+           |       e.g. TCP          |     |\n"
"|      |   Network Layer    +---------->|            UDP          |     |\n"
"|      +--------------------+           |            ICMP         |     |\n"
"|                                       |            NDP          |     |\n"
"|      +--------------------+           |            ARP          |     |\n"
"|      |   Data-link Layer  +---------->|                         |     |\n"
"|      +--------------------+           +-------------------------+     |\n"
"|                                                                       |\n"
"|      +--------------------+                                           |\n"
"|      |   Physical Layer   +---------->     Stop kidding!!!            |\n"
"|      +--------------------+                                           |\n"
"|                                                                       |\n"
"|                                                                       |\n"
"+-----------------------------------------------------------------------+\n"
;

static const unsigned short top_udp_ports[] = {
    161,      /* SNMP - should be found on all network equipment */
    135,      /* MS-RPC - should be found on all modern Windows */
    500,      /* ISAKMP - for establishing IPsec tunnels */
    137,      /* NetBIOS-NameService - should be found on old Windows */
    138,      /* NetBIOS-Datagram - should be found on old Windows */
    445,      /* SMB datagram service */
    67,       /* DHCP */
    53,       /* DNS */
    1900,     /* UPnP - Microsoft-focused local discovery */
    5353,     /* mDNS - Apple-focused local discovery */
    4500,     /* nat-t-ike - IPsec NAT traversal */
    514,      /* syslog - all Unix machiens */
    69,       /* TFTP */
    49152,    /* first of modern ephemeral ports */
    631,      /* IPP - printing protocol for Linux */
    123,      /* NTP network time protocol */
    1434,     /* MS-SQL server*/
    520,      /* RIP - routers use this protocol sometimes */
    7,        /* Echo */
    111,      /* SunRPC portmapper */
    2049,     /* SunRPC NFS */
    5683,     /* COAP */
    11211,    /* memcached */
    1701,     /* L2TP */
    27960,    /* quaked amplifier */
    1645,     /* RADIUS */
    1812,     /* RADIUS */
    1646,     /* RADIUS */
    1813,     /* RADIUS */
    3343,     /* Microsoft Cluster Services */
    2535,     /* MADCAP rfc2730 TODO FIXME */
    
};

static const unsigned short top_tcp_ports[] = {
    80, 443, 8080,          /* also web */
    21, 990,                /* FTP, oldie but goodie */
    22,                     /* SSH, so much infrastructure */
    23, 992,                /* Telnet, oldie but still around*/
    24,                     /* people put things here instead of TelnetSSH*/
    25, 465, 587, 2525,     /* SMTP email*/
    5800, 5900, 5901,       /* VNC */
    111,                    /* SunRPC */
    139, 445,               /* Microsoft Windows networking */
    135,                    /* DCEPRC, more Microsoft Windows */
    3389,                   /* Microsoft Windows RDP */
    88,                     /* Kerberos, also Microsoft windows */
    389, 636,               /* LDAP and MS Win */
    1433,                   /* MS SQL */
    53,                     /* DNS */
    2083, 2096,             /* cPanel */
    9050,                   /* ToR */
    8140,                   /* Puppet */
    11211,                  /* memcached */
    1098, 1099,             /* Java RMI */
    6000, 6001,             /* XWindows */
    5060, 5061,             /* SIP - session initiation protocool */
    554,                    /* RTSP */
    548,                    /* AFP */
    

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
    LOG(LEVEL_HINT, "saving resume file to: %s\n", filename);

    fp = fopen(filename, "wt");
    if (fp == NULL) {
        LOG(LEVEL_ERROR, "[-] FAIL: saving resume file\n");
        LOG(LEVEL_ERROR, "[-] %s: %s\n", filename, strerror(errno));
        return;
    }

    
    xconf_echo(xconf, fp);

    fclose(fp);
}

static enum Config_Res SET_scan_module(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->scan_module || xconf->echo_all){
            if (xconf->scan_module)
                fprintf(xconf->echo, "scan-module = %s\n", xconf->scan_module->name);
            else
                fprintf(xconf->echo, "scan-module = TcpSyn\n");
        }
        return 0;
    }

    xconf->scan_module = get_scan_module_by_name(value);
    if(!xconf->scan_module){
        LOG(LEVEL_ERROR, "FAIL %s: no such scan module named %s\n", name, value);
        return CONF_ERR;
    }

    return CONF_OK;
}

static enum Config_Res SET_probe_module(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->probe_module){
            fprintf(xconf->echo, "probe-module = %s\n", xconf->probe_module->name);
        }
        return 0;
    }

    xconf->probe_module = get_probe_module_by_name(value);
    if(!xconf->probe_module){
        LOG(LEVEL_ERROR, "FAIL %s: no such probe module\n", value);
        return CONF_ERR;
    }

    return CONF_OK;
}

static enum Config_Res SET_output_module(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->output.output_module){
            fprintf(xconf->echo, "output-module = %s\n", xconf->output.output_module->name);
        }
        return 0;
    }

    xconf->output.output_module = get_output_module_by_name(value);
    if(!xconf->output.output_module){
        LOG(LEVEL_ERROR, "FAIL %s: no such output module\n", value);
        return CONF_ERR;
    }

    return CONF_OK;
}

static enum Config_Res SET_output_filename(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->output.output_filename[0]){
            fprintf(xconf->echo, "output-file = %s\n",
                xconf->output.output_filename);
        }
        return 0;
    }

    safe_strcpy(xconf->output.output_filename,
        sizeof(xconf->output.output_filename), value);

    return CONF_OK;
}

static enum Config_Res SET_show_output(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->output.is_show_failed){
            fprintf(xconf->echo, "show-output = failed\n");
        }
        if (xconf->output.is_show_info){
            fprintf(xconf->echo, "show-output = info\n");
        }
        return 0;
    }

    
    if (EQUALS("failed",value)||EQUALS("fail",value)) {
        xconf->output.is_show_failed = true;
    } else if (EQUALS("info",value)||EQUALS("information",value)) {
        xconf->output.is_show_info = true;
    } else {
        LOG(LEVEL_ERROR, "FAIL %s: no item named %s\n", name, value);
        return CONF_ERR;
    }

    return CONF_OK;
}

static enum Config_Res SET_print_status(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->is_status_queue){
            fprintf(xconf->echo, "print-status = queue\n");
        }
        if (xconf->is_status_info_num){
            fprintf(xconf->echo, "print-status = info-num\n");
        }
        return 0;
    }

    
    if (EQUALS("queue",value)) {
        xconf->is_status_queue = true;
    } else if (EQUALS("info-num",value) || EQUALS("info",value)) {
        xconf->is_status_info_num = true;
    } else {
        LOG(LEVEL_ERROR, "FAIL %s: no item named %s\n", name, value);
        return CONF_ERR;
    }

    return CONF_OK;
}

static enum Config_Res SET_scan_module_args(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->scan_module_args){
            fprintf(xconf->echo, "scan-module-args = %s\n", xconf->scan_module_args);
        }
        return 0;
    }

    size_t len = strlen(value) + 1;
    if (xconf->scan_module_args)
        free(xconf->scan_module_args);
    xconf->scan_module_args = CALLOC(1, len);
    memcpy(xconf->scan_module_args, value, len);

    return CONF_OK;
}

static enum Config_Res SET_probe_module_args(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->probe_module_args){
            fprintf(xconf->echo, "probe-module-args = %s\n", xconf->probe_module_args);
        }
        return 0;
    }

    size_t len = strlen(value) + 1;
    if (xconf->probe_module_args)
        free(xconf->probe_module_args);
    xconf->probe_module_args = CALLOC(1, len);
    memcpy(xconf->probe_module_args, value, len);

    return CONF_OK;
}

static enum Config_Res SET_output_module_args(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->output.output_args){
            fprintf(xconf->echo, "output-module-args = %s\n", xconf->output.output_args);
        }
        return 0;
    }

    size_t len = strlen(value) + 1;
    if (xconf->output.output_args)
        free(xconf->output.output_args);
    xconf->output.output_args = CALLOC(1, len);
    memcpy(xconf->output.output_args, value, len);

    return CONF_OK;
}

static enum Config_Res SET_list_scan_modules(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
       return 0;
    }
    xconf->op = parseBoolean(value)?Operation_ListScanModules:xconf->op;
    return CONF_OK;
}

static enum Config_Res SET_list_probe_modules(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
       return 0;
    }
    xconf->op = parseBoolean(value)?Operation_ListProbeModules:xconf->op;
    return CONF_OK;
}

static enum Config_Res SET_list_output_modules(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
       return 0;
    }
    xconf->op = parseBoolean(value)?Operation_ListOutputModules:xconf->op;
    return CONF_OK;
}

static enum Config_Res SET_listif(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->op==Operation_ListRange || xconf->echo_all)
            fprintf(xconf->echo, "iflist = %s\n",
                xconf->op==Operation_ListAdapters?"true":"false");
        return 0;
    }

    if (parseBoolean(value))
        xconf->op = Operation_ListAdapters;
    return CONF_OK;
}

static enum Config_Res SET_list_target(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    UNUSEDPARM(value);

    if (xconf->echo) {
        return 0;
    }

    /* Read in a binary file instead of scanning the network*/
    xconf->op = Operation_ListTargets;

    return CONF_OK;
}

static enum Config_Res SET_list_range(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }

    if (parseBoolean(value))
        xconf->op = Operation_ListRange;

    return CONF_OK;
}

static enum Config_Res SET_pfring(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_pfring || xconf->echo_all)
            fprintf(xconf->echo, "pfring = %s\n", xconf->is_pfring?"true":"false");
        return 0;
    }

    xconf->is_pfring = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_nodedup(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->is_nodedup || xconf->echo_all) {
            fprintf(xconf->echo, "no-dedup = %s\n", xconf->is_nodedup?"true":"false");
        }
       return 0;
    }

    xconf->is_nodedup = parseBoolean(value);

    return CONF_OK;
}

static enum Config_Res SET_tcp_window(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->tcp_window!=0)
            fprintf(xconf->echo, "tcp-window = %u\n", xconf->tcp_window);
       return 0;
    }

    unsigned x = parseInt(value);
    if (x > 65535) {
        LOG(LEVEL_ERROR, "error: %s=<n>: expected number less than 65535\n", name);
        return CONF_ERR;
    } else {
        xconf->tcp_window = x;
    }

    return CONF_OK;
}

static enum Config_Res SET_tcp_init_window(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->tcp_init_window!=0)
            fprintf(xconf->echo, "tcp-init-window = %u\n", xconf->tcp_init_window);
       return 0;
    }

    unsigned x = parseInt(value);
    if (x > 65535) {
        LOG(LEVEL_ERROR, "error: %s=<n>: expected number less than 65535\n", name);
        return CONF_ERR;
    } else {
        xconf->tcp_init_window = x;
    }

    return CONF_OK;
}

static enum Config_Res SET_packet_ttl(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->packet_ttl!=0)
            fprintf(xconf->echo, "packet-ttl = %u\n", xconf->packet_ttl);
       return 0;
    }

    unsigned x = parseInt(value);
    if (x >= 256) {
        LOG(LEVEL_ERROR, "error: %s=<n>: expected number less than 256\n", name);
        return CONF_ERR;
    } else {
        xconf->packet_ttl = x;
    }

    return CONF_OK;
}

static enum Config_Res SET_dedup_win(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->dedup_win!=XCONF_DFT_DEDUP_WIN || xconf->echo_all)
            fprintf(xconf->echo, "dedup-win = %u\n", xconf->dedup_win);
       return 0;
    }

    if (parseInt(value)<1024) {
        LOG(LEVEL_ERROR, "FAIL: %s: dedup-win must >= 1024.\n", name);
        return CONF_ERR;
    }

    xconf->dedup_win = parseInt(value);

    return CONF_OK;
}

static enum Config_Res SET_stack_buf_count(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->stack_buf_count!=XCONF_DFT_STACK_BUF_COUNT || xconf->echo_all) {
            fprintf(xconf->echo, "stack-buf-count = %u\n", xconf->stack_buf_count);
        }
       return 0;
    }

    uint64_t v = parseInt(value);
    if (v<2048) {
        LOG(LEVEL_ERROR, "FAIL: %s: stack-buf-count must >= 2048.\n", value);
        return CONF_ERR;
    } else if (!is_power_of_two(v)) {
        LOG(LEVEL_ERROR, "FAIL: %s: stack-buf-count must be power of 2.\n", value);
        return CONF_ERR;
    } else if (v>RTE_RING_SZ_MASK) {
        LOG(LEVEL_ERROR, "FAIL: %s: stack-buf-count exceeded size limit.\n", value);
        return CONF_ERR;
    }

    xconf->stack_buf_count = v;

    return CONF_OK;
}

static enum Config_Res SET_dispatch_buf_count(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->dispatch_buf_count!=XCONF_DFT_DISPATCH_BUF_COUNT || xconf->echo_all) {
            fprintf(xconf->echo, "dispatch-buf-count = %u\n", xconf->dispatch_buf_count);
        }
       return 0;
    }

    uint64_t v = parseInt(value);
    if (v<2048) {
        LOG(LEVEL_ERROR, "FAIL: %s: dispatch-buf-count must >= 2048.\n", value);
        return CONF_ERR;
    } else if (!is_power_of_two(v)) {
        LOG(LEVEL_ERROR, "FAIL: %s: dispatch-buf-count must be power of 2.\n", value);
        return CONF_ERR;
    } else if (v>RTE_RING_SZ_MASK) {
        LOG(LEVEL_ERROR, "FAIL: %s: dispatch-buf-count exceeded size limit.\n", value);
        return CONF_ERR;
    }

    xconf->dispatch_buf_count = v;

    return CONF_OK;
}

static enum Config_Res SET_forever(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);

    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        return 0;
    }

    xconf->wait =  INT_MAX;

    return CONF_OK;
}

static enum Config_Res SET_wait(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->wait!=XCONF_DFT_WAIT || xconf->echo_all) {
            if (xconf->wait==INT_MAX)
                fprintf(xconf->echo, "forever = true\n");
            else
                fprintf(xconf->echo, "wait = %u\n", xconf->wait);
        }
        return 0;
    }

    xconf->wait = (unsigned)parseInt(value);

    return CONF_OK;
}

static enum Config_Res SET_rx_handler_count(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->rx_handler_count>1 || xconf->echo_all) {
            fprintf(xconf->echo, "rx-handler-count = %u\n", xconf->rx_handler_count);
        }
        return 0;
    }

    unsigned count = parseInt(value);
    if (count<=0) {
        LOG(LEVEL_ERROR, "FAIL: %s: receive handler thread count cannot be zero.\n", name);
        return CONF_ERR;
    } else if (!is_power_of_two(count)) {
        LOG(LEVEL_ERROR, "FAIL: %s: receive handler thread count must be power of 2.\n", value);
        return CONF_ERR;
    }

    xconf->rx_handler_count = count;

    return CONF_OK;
}

static enum Config_Res SET_tx_thread_count(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->tx_thread_count>1 || xconf->echo_all) {
            fprintf(xconf->echo, "tx-thread-count = %u\n", xconf->tx_thread_count);
        }
        return 0;
    }

    unsigned count = parseInt(value);
    if (count==0) {
        LOG(LEVEL_ERROR, "FAIL: %s: transmit thread count cannot be zero.\n", name);
        return CONF_ERR;
    }

    xconf->tx_thread_count = count;

    return CONF_OK;
}

static enum Config_Res SET_adapter(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->nic.ifname[0]) {
            fprintf(xconf->echo, "adapter = %s\n", xconf->nic.ifname);
        }
        return 0;
    }

    if (xconf->nic.ifname[0]) {
        LOG(LEVEL_HINT, "CONF: overwriting \"adapter=%s\"\n", xconf->nic.ifname);
    }
    snprintf(  xconf->nic.ifname, sizeof(xconf->nic.ifname),
        "%s", value);

    return CONF_OK;
}

static enum Config_Res SET_source_ip(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {

        if (xconf->nic.src.ipv4.first!=0 || xconf->nic.src.ipv4.last!=0) {
            ipaddress_formatted_t ipv4_first =
                ipv4address_fmt((ipv4address)(xconf->nic.src.ipv4.first));
            ipaddress_formatted_t ipv4_last =
                ipv4address_fmt((ipv4address)(xconf->nic.src.ipv4.last));
            if (xconf->nic.src.ipv4.first == xconf->nic.src.ipv4.last) {
                fprintf(xconf->echo, "source-ip = %s\n", ipv4_first.string);
            } else if (xconf->nic.src.ipv4.first < xconf->nic.src.ipv4.last) {
                fprintf(xconf->echo, "source-ip = %s-%s\n",
                    ipv4_first.string, ipv4_last.string);
            }
        }

        if (xconf->nic.src.ipv6.range) {
            ipaddress_formatted_t ipv6_first =
                ipv6address_fmt(xconf->nic.src.ipv6.first);
            ipaddress_formatted_t ipv6_last =
                ipv6address_fmt(xconf->nic.src.ipv6.last);
            if (ipv6address_is_lessthan(xconf->nic.src.ipv6.first, xconf->nic.src.ipv6.last)) {
                fprintf(xconf->echo, "source-ip = %s-%s\n",
                    ipv6_first.string, ipv6_last.string);
            } else {
                fprintf(xconf->echo, "source-ip = %s\n", ipv6_first.string);
            }
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
                LOG(LEVEL_ERROR, "FAIL: range must be even power of two: %s=%s\n",
                    name, value);
                return CONF_ERR;
            }
            xconf->nic.src.ipv4.first = range.begin;
            xconf->nic.src.ipv4.last = range.end;
            // xconf->nic.src.ipv4.range = range.end - range.begin + 1;
            xconf->nic.src.ipv4.range = 1; /*Just need one source ip now*/
            break;
        case Ipv6_Address:
            xconf->nic.src.ipv6.first = range6.begin;
            xconf->nic.src.ipv6.last = range6.end;
            xconf->nic.src.ipv6.range = 1; /* TODO: add support for more than one source */
            break;
        default:
            LOG(LEVEL_ERROR, "FAIL: bad source IP address: %s=%s\n",
                name, value);
            LOG(LEVEL_ERROR, "hint   addresses look like \"192.168.1.23\" or \"2001:db8:1::1ce9\".\n");
            return CONF_ERR;
    }

    return CONF_OK;
}

static enum Config_Res SET_source_port(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->nic.src.port.first) {
            fprintf(xconf->echo, "source-port = %d", xconf->nic.src.port.first);
            if (xconf->nic.src.port.first != xconf->nic.src.port.last) {
                /* --adapter-port <first>-<last> */
                fprintf(xconf->echo, "-%d", xconf->nic.src.port.last);
            }
            fprintf(xconf->echo, "\n");
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
        LOG(LEVEL_ERROR, "FAIL: bad source port specification: %s\n", name);
        return CONF_ERR;
    }

    /* Only allow one range of ports */
    if (ports.count != 1) {
        LOG(LEVEL_ERROR, "FAIL: only one '%s' range may be specified, found %u ranges\n",
            name, ports.count);
        return CONF_ERR;
    }

    /* verify range is even power of 2 (1, 2, 4, 8, 16, ...) */
    if (!is_power_of_two(ports.list[0].end - ports.list[0].begin + 1)) {
        LOG(LEVEL_ERROR, "FAIL: source port range must be even power of two: %s=%s\n",
            name, value);
        return CONF_ERR;
    }

    xconf->nic.src.port.first = ports.list[0].begin;
    xconf->nic.src.port.last = ports.list[0].end;
    xconf->nic.src.port.range = ports.list[0].end - ports.list[0].begin + 1;

    return CONF_OK;
}

static enum Config_Res SET_target_output(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        /* Disable comma generation for the first element */
        unsigned i = 0;
        unsigned l = 0;
        for (i=0; i<xconf->targets.ports.count; i++) {
            struct Range range = xconf->targets.ports.list[i];
            do {
                struct Range rrange = range;
                unsigned done = 0;
                if (l) {
                    fprintf(xconf->echo, ",");
                } else {
                    fprintf(xconf->echo, "port = ");
                }
                l = 1;
                if (rrange.begin >= Range_Oproto) {
                    rrange.begin -= Range_Oproto;
                    rrange.end -= Range_Oproto;
                    fprintf(xconf->echo,"O:");
                    done = 1;
                } else if (rrange.begin >= Range_SCTP) {
                    rrange.begin -= Range_SCTP;
                    rrange.end -= Range_SCTP;
                    fprintf(xconf->echo,"S:");
                    range.begin = Range_Oproto;
                } else if (rrange.begin >= Range_UDP) {
                    rrange.begin -= Range_UDP;
                    rrange.end -= Range_UDP;
                    fprintf(xconf->echo,"U:");
                    range.begin = Range_SCTP;
                } else
                    range.begin = Range_UDP;

                rrange.end = min(rrange.end, 65535);
                if (rrange.begin == rrange.end)
                    fprintf(xconf->echo, "%u", rrange.begin);
                else
                    fprintf(xconf->echo, "%u-%u", rrange.begin, rrange.end);
                if (done)
                    break;
            } while (range.begin <= range.end);
        }

        if (l)
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

static enum Config_Res SET_target_ip(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }
    
    int err;
    err = massip_add_target_string(&xconf->targets, value);
    if (err) {
        LOG(LEVEL_ERROR, "ERROR: bad IP address/range: %s\n", value);
        return CONF_ERR;
    }

    if (xconf->op == Operation_Default)
        xconf->op = Operation_Scan;

    return CONF_OK;
}

static enum Config_Res SET_adapter_snaplen(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->nic.snaplen!=XCONF_DFT_SNAPLEN || xconf->echo_all) {
            fprintf(xconf->echo, "adapter-snaplen = %u\n", xconf->nic.snaplen);
        }
        return 0;
    }
    
    xconf->nic.snaplen = (unsigned)parseInt(value);
    if (xconf->nic.snaplen > 65535) {
        LOG(LEVEL_ERROR, "FAIL: snaplen must be less than 65535.\n");
        return CONF_ERR;
    }

    return CONF_OK;
}

static enum Config_Res SET_adapter_vlan(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->nic.is_vlan) {
            fprintf(xconf->echo, "adapter-vlan = %u\n", xconf->nic.vlan_id);
        }
        return 0;
    }
    
    xconf->nic.is_vlan = 1;
    xconf->nic.vlan_id = (unsigned)parseInt(value);

    return CONF_OK;
}

static enum Config_Res SET_target_port(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }
    
    unsigned is_error = 0;

    rangelist_parse_ports(&xconf->targets.ports, value, &is_error, 0);

    if (is_error) {
        LOG(LEVEL_ERROR, "FAIL: error to set target port.\n");
        return CONF_ERR;
    }

    if (xconf->op == Operation_Default)
        xconf->op = Operation_Scan;

    return CONF_OK;
}

static enum Config_Res SET_top_port(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }
    
    unsigned maxports = parseInt(value);

    if (!maxports) {
        LOG(LEVEL_ERROR, "[-] FAIL %s: value of top-port must > 0.\n", name);
        return CONF_ERR;
    }

    struct RangeList *ports = &xconf->targets.ports;
    static const unsigned max_tcp_ports = ARRAY_SIZE(top_tcp_ports);
    static const unsigned max_udp_ports = ARRAY_SIZE(top_udp_ports);

    unsigned i;
    if (name[0]=='u') {
        LOG(LEVEL_INFO, "[+] adding UDP top-ports = %u\n", maxports);
        for (i=0; i<maxports && i<max_udp_ports; i++)
            rangelist_add_range_udp(ports,
                                top_udp_ports[i],
                                top_udp_ports[i]);
    } else {
        LOG(LEVEL_INFO, "[+] adding TCP top-ports = %u\n", maxports);
        for (i=0; i<maxports && i<max_tcp_ports; i++)
            rangelist_add_range_tcp(ports,
                                top_tcp_ports[i],
                                top_tcp_ports[i]);
    }

    /* Targets must be sorted after every change, before being used */
    rangelist_sort(ports);

    return CONF_OK;
}

static enum Config_Res SET_exclude_ip(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    int err;
    err = massip_add_target_string(&xconf->exclude, value);
    if (err) {
        LOG(LEVEL_ERROR, "ERROR: bad exclude address/range: %s\n", value);
        return CONF_ERR;
    }

    if (xconf->op == Operation_Default)
        xconf->op = Operation_Scan;
    
    return CONF_OK;
}

static enum Config_Res SET_exclude_port(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }
    unsigned defaultrange = 0;
    int err;

    err = massip_add_port_string(&xconf->exclude, value, defaultrange);
    if (err) {
        LOG(LEVEL_ERROR, "[-] FAIL: bad exclude port: %s\n", value);
        LOG(LEVEL_ERROR, "    Hint: a port is a number [0..65535]\n");
        return CONF_ERR;
    }
    if (xconf->op == Operation_Default)
        xconf->op = Operation_Scan;
    
    return CONF_OK;
}

static enum Config_Res SET_include_file(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    int err;
    const char *filename = value;

    err = massip_parse_file(&xconf->targets, filename);
    if (err) {
        LOG(LEVEL_ERROR, "[-] FAIL: error reading from include file\n");
        return CONF_ERR;
    }
    if (xconf->op == Operation_Default)
        xconf->op = Operation_Scan;
    
    return CONF_OK;
}

static enum Config_Res SET_exclude_file(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    unsigned count1 = xconf->exclude.ipv4.count;
    unsigned count2;
    int err;
    const char *filename = value;

    // LOG(LEVEL_WARNING, "EXCLUDING: %s\n", value);
    err = massip_parse_file(&xconf->exclude, filename);
    if (err) {
        LOG(LEVEL_ERROR, "[-] FAIL: error reading from exclude file\n");
        return CONF_ERR;
    }
    /* Detect if this file has made any change, otherwise don't print
        * a message */
    count2 = xconf->exclude.ipv4.count;
    if (count2 - count1)
        LOG(LEVEL_HINT, "%s: excluding %u ranges from file\n",
            value, count2 - count1);
    
    return CONF_OK;
}

static enum Config_Res SET_source_mac(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->nic.my_mac_count) {
            ipaddress_formatted_t fmt = macaddress_fmt(xconf->nic.source_mac);
            fprintf(xconf->echo, "source-mac = %s\n", fmt.string);
        }
        return 0;
    }

    /* Send packets FROM this MAC address */
    macaddress_t source_mac;
    int err;

    err = parse_mac_address(value, &source_mac);
    if (err) {
        LOG(LEVEL_ERROR, "[-] CONF: bad MAC address: %s = %s\n",
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
        LOG(LEVEL_HINT, "[-] WARNING: overwriting MAC address, was %s, now %s\n",
            fmt1.string,
            fmt2.string);
    }

    xconf->nic.source_mac = source_mac;
    xconf->nic.my_mac_count = 1;

    return CONF_OK;
}

static enum Config_Res SET_router_ip(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->nic.router_ip) {
            ipaddress_formatted_t router_ip =
                ipv4address_fmt(xconf->nic.router_ip);
            fprintf(xconf->echo, "router-ip = %s\n", router_ip.string);
        }

        return 0;
    }

    /* Send packets FROM this IP address */
    struct Range range;

    range = range_parse_ipv4(value, 0, 0);

    /* Check for bad format */
    if (range.begin != range.end) {
        LOG(LEVEL_ERROR, "FAIL: bad source IPv4 address: %s=%s\n", name, value);
        LOG(LEVEL_ERROR, "hint   addresses look like \"19.168.1.23\"\n");
        return CONF_ERR;
    }

    xconf->nic.router_ip = range.begin;

    return CONF_OK;
}

static enum Config_Res SET_router_mac(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (!macaddress_is_zero(xconf->nic.router_mac_ipv4)) {
            ipaddress_formatted_t fmt =  macaddress_fmt(xconf->nic.router_mac_ipv4);
            fprintf(xconf->echo, "router-mac-ipv4 = %s\n", fmt.string);
        }
        if (!macaddress_is_zero(xconf->nic.router_mac_ipv6)) {
            ipaddress_formatted_t fmt = macaddress_fmt(xconf->nic.router_mac_ipv6);
            fprintf(xconf->echo, "router-mac-ipv6 = %s\n", fmt.string);
        }

        return 0;
    }

    macaddress_t router_mac;
    int err;
    err = parse_mac_address(value, &router_mac);
    if (err) {
        LOG(LEVEL_ERROR, "[-] CONF: bad MAC address: %s = %s\n", name, value);
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
static enum Config_Res SET_read_conf(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        return 0;
    }

    FILE *fp;
    char *line = MALLOC(65535 * sizeof(char));

    fp = fopen(value, "rt");
    if (fp == NULL) {
        char dir[512];
        char *x;
        
        LOG(LEVEL_ERROR, "[-] FAIL: reading configuration file\n");
        LOG(LEVEL_ERROR, "[-] %s: %s\n", value, strerror(errno));

        x = getcwd(dir, sizeof(dir));
        if (x)
            LOG(LEVEL_ERROR, "[-] cwd = %s\n", dir);
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
    free(line);

    return CONF_OK;
}

static enum Config_Res SET_packet_trace(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->packet_trace || xconf->echo_all)
            fprintf(xconf->echo, "packet-trace = %s\n",
                xconf->packet_trace?"true":"false");
        return 0;
    }
    xconf->packet_trace = parseBoolean(value);
    return CONF_OK;
}

static enum Config_Res SET_ndjson_status(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_status_ndjson || xconf->echo_all)
            fprintf(xconf->echo, "ndjson-status = %s\n", xconf->is_status_ndjson?"true":"false");
        return 0;
    }
    xconf->is_status_ndjson = parseBoolean(value);
    return CONF_OK;
}

static enum Config_Res SET_append(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->output.is_append || xconf->echo_all)
            fprintf(xconf->echo, "append-output = %s\n",
                xconf->output.is_append?"true":"false");
        return 0;
    }
    xconf->output.is_append = parseBoolean(value);
    return CONF_OK;
}

static enum Config_Res SET_interactive(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->output.is_interactive || xconf->echo_all)
            fprintf(xconf->echo, "interactive = %s\n",
                xconf->output.is_interactive?"true":"false");
        return 0;
    }
    xconf->output.is_interactive = parseBoolean(value);
    return CONF_OK;
}

static enum Config_Res SET_offline(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_offline || xconf->echo_all)
            fprintf(xconf->echo, "offline = %s\n", xconf->is_offline?"true":"false");
        return 0;
    }
    xconf->is_offline = parseBoolean(value);
    return CONF_OK;
}

static enum Config_Res SET_static_seed(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_static_seed || xconf->echo_all)
            fprintf(xconf->echo, "static-seed = %s\n", xconf->is_infinite?"true":"false");
        return 0;
    }
    xconf->is_static_seed = parseBoolean(value);
    return CONF_OK;
}

static enum Config_Res SET_infinite(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_infinite || xconf->echo_all)
            fprintf(xconf->echo, "infinite = %s\n", xconf->is_infinite?"true":"false");
        return 0;
    }
    xconf->is_infinite = parseBoolean(value);
    return CONF_OK;
}

static enum Config_Res SET_fast_timeout(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        if (xconf->is_fast_timeout || xconf->echo_all) {
            if (xconf->is_fast_timeout) {
                fprintf(xconf->echo, "timeout = %"PRId64"\n", xconf->ft_spec);
            } else {
                fprintf(xconf->echo, "timeout = false\n");
            }
        }
        return 0;
    }

    if (isBoolean(value)) {
        if (parseBoolean(value)) {
            xconf->is_fast_timeout = 1;
        }
    } else if (isInteger(value)) {
        int spec = parseInt(value);
        if (spec <= 0) {
            LOG(LEVEL_ERROR, "[-] %s: need a switch word or a positive number.\n", name);
            return CONF_ERR;
        }
        xconf->is_fast_timeout = 1;
        xconf->ft_spec = (time_t)spec;
    } else
        goto fail;

    return CONF_OK;
fail:
    LOG(LEVEL_ERROR, "[-] %s: bad value: %s\n", name, value);
    return CONF_ERR;
}

static enum Config_Res SET_pcap_filename(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
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

static enum Config_Res SET_echo(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        return 0;
    }
    
    if (EQUALS("echo", name) && parseBoolean(value))
        xconf->op = Operation_Echo;
    else if (EQUALS("echo-all", name) && parseBoolean(value)) {
        xconf->op = Operation_Echo;
        xconf->echo_all = 1;
    }
    
    return CONF_OK;
}

static enum Config_Res SET_debugif(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        return 0;
    }
    
    if (parseBoolean(value))
        xconf->op = Operation_DebugIF;
    
    return CONF_OK;
}

static enum Config_Res SET_benchmark(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        return 0;
    }
    
    if (parseBoolean(value))
        xconf->op = Operation_Benchmark;
    
    return CONF_OK;
}

static enum Config_Res SET_selftest(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        return 0;
    }
    
    if (parseBoolean(value))
        xconf->op = Operation_Selftest;
    
    return CONF_OK;
}

static enum Config_Res SET_list_cidr(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    if (xconf->echo) {
        return 0;
    }
    
    if (parseBoolean(value))
        xconf->op = Operation_ListCidr;
    
    return CONF_OK;
}

static enum Config_Res SET_lan_mode(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }
    
    if (parseBoolean(value)) {
        SET_router_mac(xconf, "router-mac", "ff-ff-ff-ff-ff-ff");
    }
    
    return CONF_OK;
}

static enum Config_Res SET_bypass_os(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_bypass_os || xconf->echo_all)
            fprintf(xconf->echo, "bypass-os = %s",
                xconf->is_bypass_os?"true":"false");
        return 0;
    }
    
    xconf->is_bypass_os = parseBoolean(value);
    
    return CONF_OK;
}

static enum Config_Res SET_fake_router_mac(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }
    
    if (parseBoolean(value)) {
        SET_router_mac(xconf, "router-mac", "01-02-03-04-05-06");
    }
    
    return CONF_OK;
}

static enum Config_Res SET_rate(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
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
            LOG(LEVEL_ERROR, "CONF: non-digit in rate spec: %s=%s\n", name, value);
            return CONF_ERR;
        }
        rate = rate * 10.0 + (c - '0');
    }
    
    if (value[i] == '.') {
        i++;
        while (value[i]) {
            char c = value[i];
            if (c < '0' || '9' < c) {
                LOG(LEVEL_ERROR, "CONF: non-digit in rate spec: %s=%s\n",
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

static enum Config_Res SET_max_packet_len(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->max_packet_len!=XCONF_DFT_MAX_PKT_LEN || xconf->echo_all) {
            fprintf(xconf->echo, "max-packet-len = %u\n", xconf->max_packet_len);
        }
        return 0;
    }
    xconf->max_packet_len = parseInt(value);
    return CONF_OK;
}

static enum Config_Res SET_resume_count(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->resume.count!=0 || xconf->echo_all) {
            fprintf(xconf->echo, "resume-count = %" PRIu64 "\n", xconf->resume.count);
        }
        return 0;
    }
    xconf->resume.count = parseInt(value);
    return CONF_OK;
}

static enum Config_Res SET_resume_index(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->resume.index!=0 || xconf->echo_all) {
            fprintf(xconf->echo, "resume-index = %" PRIu64 "\n", xconf->resume.index);
        }
        return 0;
    }
    xconf->resume.index = parseInt(value);
    return CONF_OK;
}

static enum Config_Res SET_no_bpf(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_no_bpf || xconf->echo_all)
            fprintf(xconf->echo, "no-bpf-filter = %s\n",
                xconf->is_no_bpf?"true":"false");
        return 0;
    }
    xconf->is_no_bpf = parseBoolean(value);
    return CONF_OK;
}

static enum Config_Res SET_bpf_filter(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->bpf_filter)
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


static enum Config_Res SET_seed(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
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

static enum Config_Res SET_nothing(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }
    return CONF_OK;
}

static enum Config_Res SET_version(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }

    xconf->op = Operation_PrintVersion;

    return CONF_OK;
}

static enum Config_Res SET_usage(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }

    xconf_print_usage();

    return CONF_ERR;
}

static enum Config_Res SET_print_intro(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }

    xconf->op = Operation_PrintIntro;

    return CONF_OK;
}

static enum Config_Res SET_print_help(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }

    xconf->op = Operation_PrintHelp;

    return CONF_OK;
}

static enum Config_Res SET_log_level(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(value);
    if (xconf->echo) {
        int level = LOG_get_level();
        if (level > 0) {
            for (unsigned i=0; i<level; i++) {
                fprintf(xconf->echo, "%c", 'd');
            }
            fprintf(xconf->echo, " = true\n");
        }
        return 0;
    }

    LOG_add_level(strlen(name));
    
    return CONF_OK;
}

static enum Config_Res SET_shard(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
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
        LOG(LEVEL_ERROR, "FAIL: shard index can't be zero\n");
        LOG(LEVEL_ERROR, "hint   it goes like 1/4 2/4 3/4 4/4\n");
        return CONF_ERR;
    }
    if (one > of) {
        LOG(LEVEL_ERROR, "FAIL: shard spec is wrong\n");
        LOG(LEVEL_ERROR, "hint   it goes like 1/4 2/4 3/4 4/4\n");
        return CONF_ERR;
    }
    xconf->shard.one = one;
    xconf->shard.of = of;
    return CONF_OK;
}

static enum Config_Res SET_tcp_mss(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;

    if (xconf->echo) {
        if (xconf->templ_opts) {
            switch (xconf->templ_opts->tcp.is_mss) {
                case Default:
                    break;
                case Add:
                    if (xconf->templ_opts->tcp.mss == TCP_DEFAULT_MSS)
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
        xconf->templ_opts = CALLOC(1, sizeof(*xconf->templ_opts));

    if (value == 0 || value[0] == '\0') {
        /* no following parameter, so interpret this to mean "enable" */
        xconf->templ_opts->tcp.is_mss = Add;
        xconf->templ_opts->tcp.mss = TCP_DEFAULT_MSS;
    } else if (isBoolean(value)) {
        /* looking for "enable" or "disable", but any boolean works,
         * like "true/false" or "off/on" */
        if (parseBoolean(value)) {
            xconf->templ_opts->tcp.is_mss = Add;
            xconf->templ_opts->tcp.mss = TCP_DEFAULT_MSS;
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
    LOG(LEVEL_ERROR, "[-] %s: bad value: %s\n", name, value);
    return CONF_ERR;
}

static enum Config_Res SET_tcp_wscale(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
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
        xconf->templ_opts = CALLOC(1, sizeof(*xconf->templ_opts));

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
    LOG(LEVEL_ERROR, "[-] %s: bad value: %s\n", name, value);
    return CONF_ERR;
}

static enum Config_Res SET_tcp_tsecho(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
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
        xconf->templ_opts = CALLOC(1, sizeof(*xconf->templ_opts));

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
    LOG(LEVEL_ERROR, "[-] %s: bad value: %s\n", name, value);
    return CONF_ERR;
}

static enum Config_Res SET_tcp_sackok(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
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
        xconf->templ_opts = CALLOC(1, sizeof(*xconf->templ_opts));

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
    LOG(LEVEL_ERROR, "[-] %s: bad value: %s\n", name, value);
    return CONF_ERR;
}

static enum Config_Res SET_repeat(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->repeat || xconf->echo_all)
            fprintf(xconf->echo, "repeat = %"PRIu64"\n", xconf->repeat);
        return 0;
    }

    xconf->repeat = (unsigned)parseInt(value);
    if (xconf->repeat) {
        xconf->is_infinite = 1;
    } else {
        LOG(LEVEL_ERROR, "FAIL: repeat must > 0.\n");
        return CONF_ERR;
    }
    return CONF_OK;
}

static enum Config_Res SET_blackrock_rounds(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->blackrock_rounds!=XCONF_DFT_BLACKROCK_ROUND || xconf->echo_all)
            fprintf(xconf->echo, "blackrock-rounds = %u\n", xconf->blackrock_rounds);
        return 0;
    }

    xconf->blackrock_rounds = (unsigned)parseInt(value);
    return CONF_OK;
}

static enum Config_Res SET_send_queue(void *conf, const char *name, const char *value)
{
    struct Xconf *xconf = (struct Xconf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_sendq || xconf->echo_all)
            fprintf(xconf->echo, "send-queue = %s\n", xconf->is_sendq?"true":"false");
        return 0;
    }

    xconf->is_sendq = parseBoolean(value);
    return CONF_OK;
}

struct ConfigParam config_parameters[] = {
    {"BASIC:", SET_nothing, 0, {0}, NULL},

    {
        "seed",
        SET_seed,
        F_NONE,
        {0},
        "Set a global seed for randomizing of target addresses(ports), and to "
        "generate cookies in some ScanModules & ProbeModules."
        "Specify an integer that seeds the random number generator for randomizing"
        " targets and cookie(for ScanModules & ProbeModules) generation. Using a"
        " different seed will cause packets to be sent in a different random "
        "order. Instead of an integer, the string time can be specified, which "
        "seeds using the local timestamp, automatically generating a different "
        "random order of scans. If no seed specified, time is the default."
    },
    {
        "rate",
        SET_rate,
        F_NONE,
        {"max-rate", 0},
        "Specifies the desired rate for transmitting packets. This can be very "
        "small numbers, like 0.1 for transmitting packets at rates of one every "
        "10 seconds, for very large numbers like 10000000, which attempts to "
        "transmit at 10 million packets/second. In usual experience, Windows can"
        " do 250 thousand packets per second, and latest versions of Linux can "
        "do 2.5 million packets per second. The PF_RING driver is needed to get "
        "to 25 million packets/second. This rate(packets per second) is for total"
        " speed of all transmit threads."
    },
    {
        "wait",
        SET_wait,
        F_NUMABLE,
        {"cooldown", 0},
        "How many seconds should "XTATE_FIRST_UPPER_NAME" waiting and handling "
        "incoming packets after all transmit threads finished. Default is 10s."
        "Specifies the number of seconds after transmit is done to wait for "
        "receiving packets before exiting the program. The default is 10 "
        "seconds."
    },
    {
        "forever",
        SET_forever,
        F_BOOL,
        {0},
        "Set `--wait` to a large enough time."
    },
    {
        "shard",
        SET_shard,
        F_NONE,
        {"shards", 0},
        "Set a string like \"x/y\" to splits the scan among instances. x is the "
        "id for this scan, while y is the total number of instances. For example,"
        " --shard 1/2 tells an instance to send every other packet, starting with"
        " index 0. Likewise, --shard 2/2 sends every other packet, but starting "
        "with index 1, so that it doesn't overlap with the first example."
    },
    {
        "tx-thread-count",
        SET_tx_thread_count,
        F_NUMABLE,
        {"tx-count", "tx-num", 0},
        "Specify the number of transmit threads. "XTATE_FIRST_UPPER_NAME" could"
        " has multiple transmit threads but only one receive thread. Every "
        "thread will be lock on a CPU kernel if the number of all threads is no"
        " more than kernel's."
    },
    {
        "rx-handler-count",
        SET_rx_handler_count,
        F_NUMABLE,
        {"rx-count", "rx-num", 0},
        "Specify the number of receive handler threads. "XTATE_FIRST_UPPER_NAME" could"
        " has multiple receive handler threads but only one receive thread. Every "
        "handler thread will be dispatched recv packets by (dst_IP, dst_Port, "
        "src_IP, src_Port) and executes the `handler_cb` of ScanModule. This is "
        "for some necessary but slow action while ScanModule handling consecutive"
        " communication (e.g. stateful TLS connection). If the action is irrespective"
        " with consecutive communication (e.g. results processing), it is better"
        " to use special thread-pool.\n"
        "The number of receive handler must be the power of 2. (Default 1)"
    },
    {
        "d",
        SET_log_level,
        F_BOOL,
        {"dd", "ddd", "dddd", "ddddd", 0},
        "Set the log level. You can set \"-d\", \"-dd\", \"-ddd\" and etc."
    },
    {
        "version",
        SET_version,
        F_BOOL,
        {"v", 0},
        "Print the version and compilation info."
    },
    {
        "usage",
        SET_usage,
        F_BOOL,
        {0},
        "Print basic usage with some examples."
    },
    {
        "help",
        SET_print_help,
        F_BOOL,
        {"h", "?", 0},
        "Print the detailed help text of all parameters."
    },
    {
        "introduction",
        SET_print_intro,
        F_BOOL,
        {"intro", 0},
        "Print the introduction of work flow."
    },

    {"TARGET:", SET_nothing, 0, {0}, NULL},

    {
        "target-ip",
        SET_target_ip,
        F_NONE,
        {"range", "ranges", "dst-ip", "ip", 0},
        "Specifies an IP address or range as target "XTATE_FIRST_UPPER_NAME". "
        "There are three valid formats. The first is a single IP address like "
        "192.168.0.1 or 2001:db8::1. The second is a range like 10.0.0.1-10.0.0.100."
        " The third is a CIDR address, like 0.0.0.0/0 or 2001:db8::/90. At least"
        " one target must be specified. Multiple targets can be specified. This "
        "can be specified as multiple options separated by a comma as a single "
        "option, such as 10.0.0.0/8,192.168.0.1,2001:db8::1."
    },
    {
        "port",
        SET_target_port,
        F_NONE,
        {"p", "ports", 0},
        "Specifies the port(s) to be scanned. A single port can be specified, "
        "like -p 80. A range of ports can be specified, like -p 20-25. A list of"
        " ports/ranges can be specified, like -p 80,20-25. UDP ports can be"
        " specified, like --ports U:161,u:1024-1100. SCTP ports can be specified"
        " like --ports S:36412,s:38412, too.\n"
        "NOTE: We also support `--ports O:16` to present non-port number in range"
        " [0..65535] for some ScanModules."
    },
    {
        "top-port",
        SET_top_port,
        F_NUMABLE,
        {"top", "tcp-top", "tcp-top-port", 0},
        "Add a number of tcp ports to scan from predefined top list."
    },
    {
        "udp-top-port",
        SET_top_port,
        F_NUMABLE,
        {"udp-top", 0},
        "Add a number of udp ports to scan from predefined top list."
    },
    {
        "include-file",
        SET_include_file,
        F_NONE,
        {"iL", 0},
        "Reads in a list of ranges from specified file to scan, in the same "
        "target format described above for IP addresses and ranges. This file "
        "can contain millions of addresses and ranges."
    },
    {
        "exclude",
        SET_exclude_ip,
        F_NONE,
        {"exclude-range", "exlude-ranges", "exclude-ip", 0},
        "Blacklist an IP address or range, preventing it from being scanned. "
        "This overrides any target specification, guaranteeing that this "
        "address/range won't be scanned. This has the same format as the normal "
        "target specification."
    },
    {
        "exclude-port",
        SET_exclude_port,
        F_NONE,
        {"exclude-ports", 0},
        "Blacklist ports to preventing it from being scanned. This overrides "
        "any port specification. This has the same format as the normal port "
        "specification."
    },
    {
        "exclude-file",
        SET_exclude_file,
        F_NONE,
        {0},
        "Reads in a list of exclude ranges, in the same target format described "
        "above. These ranges override any targets, preventing them from being "
        "scanned."
    },

    {"INTERFACE:", SET_nothing, 0, {0}, NULL},

    {
        "adapter",
        SET_adapter,
        F_NONE,
        {"if", "interface", 0},
        "Use the named raw network interface, such as \"eth0\" or \"dna1\". If "
        "not specified, the first network interface found with a default gateway"
        " will be used."
    },
    {
        "source-ip",
        SET_source_ip,
        F_NONE,
        {"src-ip", 0},
        "Send packets using this IP address. If not specified, then the first IP"
        " address bound to the network interface will be used. Instead of a "
        "single IP address, a range may be specified.\n"
        "NOTE: The size of the range must be an even power of 2, such as "
        "1, 2, 4, 8, 16, 1024 etc."
    },
    {
        "source-port",
        SET_source_port,
        F_NONE,
        {"src-port", 0},
        "Send packets using this port number as the source. If not specified, a"
        " random port will be chosen in the range 40000 through 60000. This port"
        " should be filtered by the host firewall (like iptables) to prevent the"
        " host network stack from interfering with arriving packets. Instead of "
        "a single port, a range can be specified, like 40000-40003.\n"
        "NOTE: The size of the range must be an even power of 2, such as "
        "the example above that has a total of 4 addresses."
    },
    {
        "source-mac",
        SET_source_mac,
        F_NONE,
        {"src-mac", 0},
        "Send packets using this as the source MAC address. If not specified, "
        "then the first MAC address bound to the network interface will be used."
    },
    {
        "router-ip",
        SET_router_ip,
        F_NONE,
        {0},
        "Set an IP as router's address."
    },
    {
        "router-mac",
        SET_router_mac,
        F_NONE,
        {"gateway-mac", "router-mac-ipv4", "router-mac-ipv6", 0},
        "Send packets to this MAC address as the destination. If not specified, "
        "then the gateway address of the network interface will be get by ARP "
        "and used.\n"
        "NOTE: We could specify different router MAC address for IPv4 and "
        "IPv6 by adding a suffix to the flag."
    },
    {
        "adapter-vlan",
        SET_adapter_vlan,
        F_NUMABLE,
        {"vlan", "vlan-id", 0},
        "Send packets using this 802.1q VLAN ID."
    },
    {
        "adapter-snaplen",
        SET_adapter_snaplen,
        F_NUMABLE,
        {"snaplen", 0},
        "Set the maximum packet capture len of pcap or pfring. It means we can "
        "just got snaplen size at most for any packet even just like a kind of "
        "truncation. This is a non-commonly used switch for some special "
        "experimental tests. Default snaplen is 65535 and must be less than 65535.\n"
        "NOTE: Be cared to the interaction with tcp-win and max-packet-len."
    },
    {
        "lan-mode",
        SET_lan_mode,
        F_BOOL,
        {"local", "lan", 0},
        "Set the router MAC address to a broadcast address(ff-ff-ff-ff-ff-ff). "
        "This can make "XTATE_FIRST_UPPER_NAME" be able to scan in a local network.\n"
        "NOTE: This flag must set while we do some layer-2 protocol scan "
        "like ARP."
    },
    {
        "fake-router-mac",
        SET_fake_router_mac,
        F_BOOL,
        {"no-router-mac", 0},
        "Set the router MAC address to a invalid address(01-02-03-04-05-06). "
        "This can stop "XTATE_FIRST_UPPER_NAME" to resolve router MAC address."
        "It's useful when the ScanModule will specify destination MAC address "
        "dynamicly for different target. e.g. NdpNsScan.\n"
        "HINT: If we want to test the highest sending rate and not bother anyone"
        ", this param would be helpful with `--infinite`."
    },
    {
        "bypass-os",
        SET_bypass_os,
        F_BOOL,
        {"bypass", 0},
        "Completely bypass the OS protocol stack. This means we can set a proper"
        " `--src-ip`(in the local subnet) and `--src-mac` different from the OS "
        "to scan. Because "XTATE_FIRST_UPPER_NAME" will do reponse to special ARP "
        "& NDP request for our new IP as if we are real member of the local "
        "subnet.\n"
        "NOTE: There's no need to set some firewall rules for Linux while we are"
        " in bypassing mode. And we can't use the feature of OS protocol stack "
        "like responsing TCP RST or ICMP Port Unreachable."
    },

    {"OPERATION:", SET_nothing, 0, {0}, NULL},

    {
        "echo",
        SET_echo,
        F_BOOL,
        {"echo-all", 0},
        "Do not run, but instead print the current configuration. Use --echo to "
        "dump configurations that are different from default value. Use --echo-all"
        " to dump configurations with explicit value. The configurations can be "
        "save to a file as config and then be used with the --conf option."
    },
    {
        "debug-if",
        SET_debugif,
        F_BOOL,
        {0},
        "Run special selftest for code about interface. This is useful to figure"
        " out why the interface doesn't work."
    },
    {
        "benchmark",
        SET_benchmark,
        F_BOOL,
        {"bench", 0},
        "Run a global benchmark for key units."
    },
    {
        "selftest",
        SET_selftest,
        F_BOOL,
        {"regress", "regression", 0},
        "Run a global regression test to check if new changes in code healthy."
    },
    {
        "list-cidr",
        SET_list_cidr,
        F_BOOL,
        {"cidr", 0},
        "Do not run, but instead print all IP targets in CIDR format."
    },
    {
        "list-range",
        SET_list_range,
        F_BOOL,
        {"list-ranges", 0},
        "Do not run, but instead print all IP targets in ranges."
    },
    {
        "list-target",
        SET_list_target,
        F_BOOL,
        {"list-targets", 0},
        "Do not run, but instead print every unique IP targets in random."
    },
    {
        "list-if",
        SET_listif,
        F_BOOL,
        {"list-interface", "list-adapter", 0},
        "Do not run, but instead print informations of all adapters in this machine."
    },

    {"SCAN MODULES:", SET_nothing, 0, {0}, NULL},

    {
        "scan-module",
        SET_scan_module,
        F_NONE,
        {"scan", 0},
        "Specifies a ScanModule to perform scanning. Use --list-scan to get "
        "informations of all ScanModules.\nNOTE: A ScanModule must be used in "
        "every time we scan. TcpSynModule will be default if we did not specify."
    },
    {
        "list-scan-modules",
        SET_list_scan_modules,
        F_BOOL,
        {"list-scan-module", "list-scan", "list-scans", 0},
        "List informations of all ScanModules."
    },
    {
        "scan-module-args",
        SET_scan_module_args,
        F_NONE,
        {"scan-module-arg", "scan-args", "scan-arg", 0},
        "Specifies an argument for used ScanModule."
    },

    {"PROBE MODULES:", SET_nothing, 0, {0}, NULL},

    {
        "probe-module",
        SET_probe_module,
        F_NONE,
        {"probe", 0},
        "Specifies a ProbeModule for used ScanModule to perform scanning. Use "
        "--list-probe to get informations of all ProbeModules.\nNOTE: ProbeModule"
        " is not required for all ScanModules and different ScanModule expects "
        "different type of ProbeModule."
    },
    {
        "list-probe-modules",
        SET_list_probe_modules,
        F_BOOL,
        {"list-probe-module", "list-probe", "list-probes", 0},
        "List informations of all ProbeModules."
    },
    {
        "probe-module-args",
        SET_probe_module_args,
        F_NONE,
        {"probe-module-arg", "probe-args", "probe-arg", 0},
        "Specifies an argument for used ProbeModule."
    },

    {"OUTPUT MODULES:", SET_nothing, 0, {0}, NULL},

    {
        "output-module",
        SET_output_module,
        F_NONE,
        {"output", "out", 0},
        "Specifies an OutputModule for outputing results in special way. Use "
        "--list-output to get informations of all OutputModules. OutputModule"
        " is non-essential because "XTATE_FIRST_UPPER_NAME" output results to "
        "stdout in default.\n"
        "NOTE: "XTATE_FIRST_UPPER_NAME" won't output to stdout if we specified "
        "an OutputModule unless we use `--interactive` switch."
    },
    {
        "list-output-modules",
        SET_list_output_modules,
        F_BOOL,
        {"list-output-module", "list-output", "list-out", 0},
        "List informations of all OutputModules."
    },
    {
        "output-module-args",
        SET_output_module_args,
        F_NONE,
        {"output-module-arg", "output-arg", "out-arg", 0},
        "Specifies an argument for used OutputModule."
    },
    {
        "output-file",
        SET_output_filename,
        F_NONE,
        {"out-file", "o", 0},
        "Specifies a file for OutputModule."
    },
    {
        "append-output",
        SET_append,
        F_BOOL,
        {"output-append", "append", 0},
        "Causes output to append mode, rather than overwriting. OutputModules "
        "have different performance with this switch."
    },
    {
        "interactive",
        SET_interactive,
        F_BOOL,
        {"interact", 0},
        "Also print the results to screen while specifying an OutputModule."
    },
    {
        "show-output",
        SET_show_output,
        F_NONE,
        {"show-out", "show", 0},
        "Tells which type of results should be showed explicitly, such as:\n"
        "'failed' for those ports that respond with a RST on TCP.\n"
        "'info' for type of information or hint."
    },

    {"XTATUS:", SET_nothing, 0, {0}, NULL},

    {
        "print-status",
        SET_print_status,
        F_NONE,
        {"print-st", "print", 0},
        "Tells which type of status should be printed explicitly, such as:\n"
        "'queue' for real-time capacity of transmit queue and receive queues.\n"
        "'info-num' for count of information type results."
    },
    {
        "ndjson-status",
        SET_ndjson_status,
        F_BOOL,
        {"status-ndjson", 0},
        "Print status information in NDJSON format(Newline Delimited JSON) while"
        " running."
    },

    {"PACKET ATTRIBUTE:", SET_nothing, 0, {0}, NULL},

    {
        "packet-ttl",
        SET_packet_ttl,
        F_NUMABLE,
        {"ttl", 0},
        "Specifies the TTL of outgoing packets, defaults to 255."
    },
    {
        "tcp-init-window",
        SET_tcp_init_window,
        F_NUMABLE,
        {"tcp-init-win", 0},
        "Specifies what value of Window should TCP SYN packets use. The default "
        "value of TCP Window for TCP SYN packets is 64240."
    },
    {
        "tcp-window",
        SET_tcp_window,
        F_NUMABLE,
        {"tcp-win", 0},
        "Specifies what value of Window should TCP packets(except for SYN) use. "
        "The default value of TCP Window for TCP packets(except SYN) is 1024.\n"
        "NOTE: This value could affects some ScanModules working like ZBanner "
        "and limit communicating rate of stateful ScanModules."
        "Be cared to the interaction with snaplen and max-packet-len."
    },
    {
        "tcp-wscale",
        SET_tcp_wscale,
        F_NUMABLE,
        {0},
        "Specifies whether or what value of TCP Window Scaling option should TCP"
        " SYN packets use. e.g. --tcp-wscale true, --tcp-wscale 8. The default "
        "value of Window Scaling is 3 and not be used in template of TCP SYN "
        "packet."
    },
    {
        "tcp-mss",
        SET_tcp_mss,
        F_NUMABLE,
        {0},
        "Specifies whether or what value of TCP MMS(Maximum Segment Size) option"
        " should TCP SYN packets use. e.g. --tcp-mss false, --tcp-mss 64000. The "
        "default MMS value is 1460."
    },
    {
        "tcp-sackok",
        SET_tcp_sackok,
        F_BOOL,
        {"tcp-sack",0},
        "Specifies whether should TCP SYN packets use TCP Selective Acknowledgement"
        " option. e.g. --tcp-sackok true. The default template of TCP SYN packet"
        " does not use TCP Selective Acknowledgement option."
    },
    {
        "tcp-tsecho",
        SET_tcp_tsecho,
        F_NUMABLE,
        {0},
        "Specifies whether or what value of timestamp in TCP Timestamp option"
        " should TCP SYN packets use for timestamp echoing. e.g. --tcp-tsecho "
        "true, --tcp-tsecho <value>. The default timestamp value is 0x12345678 "
        " and is not be used in template of TCP SYN packet."
    },
    {
        "packet-trace",
        SET_packet_trace,
        F_BOOL,
        {"trace-packet", 0},
        "Prints a summary of packets we sent and received. This is useful for "
        "debugging at low rates, like a few packets per second, but will "
        "overwhelm the terminal at high rates."
    },
    {
        "bpf-filter",
        SET_bpf_filter,
        F_NONE,
        {0},
        "Specifies a string as BPF filter addition for ScanModule we use at pcap"
        " mode. NOTE: Every ScanModule has its own BPF filter and we can observe"
        " them with --list-scan. The BPF filter we set with --bpf-filter will "
        "constrain the packets we receive with ScanModules'."
    },
    {
        "no-bpf-filter",
        SET_no_bpf,
        F_BOOL,
        {"no-bpf", 0},
        "Do not compile any BPF filter from ScanModules or users. Some machines"
        " does not support part or all of BPF filters and this switch makes "
        XTATE_UPPER_NAME" working again."
    },
    {
        "max-packet-len",
        SET_max_packet_len,
        F_NUMABLE,
        {"max-pkt-len", 0},
        XTATE_UPPER_NAME" won't handle a received packet that is more than "
        "max-packet-len. Default is 1514."
        "NOTE: Be cared to the interaction with tcp-win and max-packet-len."
    },

    {"MISC:", SET_nothing, 0, {0}, NULL},

    {
        "conf",
        SET_read_conf,
        F_NONE,
        {"config", "resume", 0},
        "Reads in a configuration file. If not specified, then will read from "
        "/etc/xtate/xtate.conf by default. We could specifies a configuration "
        "file generated by "XTATE_UPPER_NAME" automatically after break by user"
        " to resume an unfinished scanning."
    },
    {
        "resume-index",
        SET_resume_index,
        F_NUMABLE,
        {0},
        "The point in the scan at when it was paused."
    },
    {
        "resume-count",
        SET_resume_count,
        F_NUMABLE,
        {"target-count", 0},
        "The maximum number of targets to scan before exiting. This is useful "
        "with the --resume-index to chop up a scan and split it among multiple "
        "instances, though the --shards option might be better.\n"
        "NOTE: This causes inifinite pause after finished resume-count and waits"
        " user input <ctrl-c> to exit."
    },
    {
        "pcap-filename",
        SET_pcap_filename,
        F_NONE,
        {"pcap",0},
        "Saves received packets (but not transmitted packets) to the "
        "libpcap-format file."
    },
    {
        "timeout",
        SET_fast_timeout,
        F_NUMABLE,
        {"use-timeout", 0},
        "Specifies whether or how many timeouts(sec) should ScanModule use like"
        " --timeout true, --timeout 15. Some ScanModules could use timeout "
        "function of "XTATE_UPPER_NAME" to result some unresponsed targets and "
        "do some operation."
    },
    {
        "no-dedup",
        SET_nodedup,
        F_BOOL,
        {0},
        "Do not deduplicate the results even if ScanModule use deduplication."
    },
    {
        "dedup-win",
        SET_dedup_win,
        F_NUMABLE,
        {0},
        "Set the window size of deduplication table. Default size if 1000000."
    },
    {
        "stack-buf-count",
        SET_stack_buf_count,
        F_NUMABLE,
        {"tx-buf-count", 0},
        "Set the buffer size of packets queue(stack) from receive thread to transmit "
        "thread.\n"
        "The value of packets queue must be power of 2. (Default 16384)"
    },
    {
        "dispatch-buf-count",
        SET_dispatch_buf_count,
        F_NUMABLE,
        {"rx-buf-count", 0},
        "Set the buffer size of dispatch queue from receive thread to receive "
        "handler threads.\n"
        "The value of packets queue must be power of 2. (Default 16384)"
    },
    {
        "pfring",
        SET_pfring,
        F_BOOL,
        {0},
        "Force the use of the PF_RING driver. The program will exit if PF_RING "
        "DNA drvers are not available."
    },
    {
        "send-queue",
        SET_send_queue,
        F_BOOL,
        {"sendq", 0},
        "Use sendqueue feature of Npcap/Winpcap on Windows to transmit packets. "
        "The transmit rate on Windows is really slow, like 40-kpps. The speed "
        "can be increased by using the sendqueue feature to roughly 300-kpps."
    },
    {
        "offline",
        SET_offline,
        F_BOOL,
        {"dry-run", 0},
        "Do not actually transmit packets. This is useful with a low rate and "
        "--packet-trace to look at what packets might've been transmitted. Or, "
        "it's useful with --rate 100000000 in order to benchmark how fast "
        "transmit would work (assuming a zero-overhead driver). PF_RING is about"
        " 20% slower than the benchmark result from offline mode."
    },
    {
        "infinite",
        SET_infinite,
        F_BOOL,
        {0},
        "Scan the target again and again. Not stop until we hit <Ctrl-C>. This "
        "is useful for us to test the some performance of "XTATE_FIRST_UPPER_NAME
        ". The seed will update in every loop while setting infinite mode.\n"
        "HINT: If we just want to test the highest sending rate, try to set an "
        "invalid router mac like `--router-mac 11:22:33:44:55:66` or use `--fake"
        "-router-mac` to send packets in local network.\n"
        "NOTE: We should be careful to the deduplication in the infinite mode."
    },
    {
        "repeat",
        SET_repeat,
        F_NUMABLE,
        {"repeats", 0},
        "How many times "XTATE_FIRST_UPPER_NAME" should repeat for all targets."
        " It also means the hit count for every target + 1. So default is 0."
        " `--infinite` will be automatically set when we use repeat.\n"
        "NOTE: We should be careful to the deduplication in the repeat mode."
    },
    {
        "static-seed",
        SET_static_seed,
        F_BOOL,
        {"keep-seed", 0},
        "Use same seed to pick up addresses in infinite mode. "
        XTATE_FIRST_UPPER_NAME" changes seed for every round to make a different"
        " scan order while repeating. We can use static-seed to keep order of "
        "all rounds."
    },
    {
        "blackrock-rounds",
        SET_blackrock_rounds,
        F_NUMABLE,
        {"blackrock-round", 0},
        "Specifies the number of round in blackrock algorithm for targets "
        "randomization. It's 14 rounds in default to give a better statistical "
        "distribution with a low impact on scan rate."
    },


    /*Put it at last for better "help" output*/
    {"TARGET_OUTPUT:", SET_target_output, 0, {0}, NULL},

    {0}
};

/***************************************************************************
 * Exit process if CONF_ERR happens.
 ***************************************************************************/
void
xconf_set_parameter(struct Xconf *xconf,
                      const char *name, const char *value)
{
    set_one_parameter(xconf, config_parameters, name, value);
}


/***************************************************************************
 * Read the configuration from the command-line.
 * Called by 'main()' when starting up.
 ***************************************************************************/
void
xconf_command_line(struct Xconf *xconf, int argc, char *argv[])
{
    set_parameters_from_args(xconf, config_parameters, argc-1, argv+1);

    if (xconf->shard.of > 1 && xconf->seed == 0) {
        LOG(LEVEL_ERROR, "[-] WARNING: --seed <num> is not specified\n    HINT: all shards must share the same seed\n");
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
    unsigned i;
    
    /*
     * Print all configuration parameters
     */
    xconf->echo = fp;

    SET_PARAMETER tmp = NULL;
    for (i=0; config_parameters[i].name; i++) {
        /**
         * We may use same `set` func more than one times back-to-back
         * in config_paramiters.
         * Do a dedup easily when echoing.
        */
        if (config_parameters[i].set == tmp)
            continue;
        tmp = config_parameters[i].set;

        config_parameters[i].set(xconf, 0, 0);
    }
    xconf->echo = 0;
    xconf->echo_all = 0;
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
bool xconf_contains(const char *x, int argc, char **argv)
{
    int i;

    for (i=0; i<argc; i++) {
        if (strcmp(argv[i], x) == 0)
            return true;
    }

    return false;
}

void xconf_print_intro()
{
    printf("\n");
    printf("Welcome to "XTATE_FIRST_UPPER_NAME"!");
    printf("\n");
    xprint(XTATE_FOR, 2, 80);
    printf("\n");
    printf("\n");
    printf("  Author : "XTATE_AUTHOR_NAME"\n");
    printf("  Github : "XTATE_GITHUB"\n");
    printf("  Contact: "XTATE_AUTHOR_MAIL"\n");
    printf("\n");
    printf("\n");
    printf("\n");
    printf("This is how "XTATE_FIRST_UPPER_NAME" working internally:\n");
    printf("\n");
    printf(work_flow);
    printf("\n");
    printf("\n");
    printf("\n");
    printf("This is what ScanModules and ProbeModules mean:\n");
    printf("\n");
    printf(scan_probe_module_rela);
    printf("\n");
    printf("\n");
}

void xconf_print_usage()
{
    printf("\n\n\n");
    xprint_with_head(ascii_xtate2, 10, 80);
    printf("\n                             "XTATE_GOD"\n\n");
    printf("\n");

    printf("\n");
    printf("Welcome to "XTATE_FIRST_UPPER_NAME"!");
    printf("\n");
    xprint(XTATE_FOR, 2, 80);
    printf("\n");
    printf("\n");
    printf("  Author : "XTATE_AUTHOR_NAME"\n");
    printf("  Github : "XTATE_GITHUB"\n");
    printf("  Contact: "XTATE_AUTHOR_MAIL"\n");
    printf("\n");
    printf("usage format:\n");
    printf("  "XTATE_NAME" [options] [-range IPs -p PORTs [-scan SCANMODULE [-probe PROBEMODULE]]]\n");
    printf("\n");
    printf("original examples of "XTATE_NAME":\n");
    printf("\n");
    printf("  "XTATE_NAME" -p 80,8000-8100 -range 10.0.0.0/8 --rate=10000\n");
    xprint("use default TcpSyn ScanModule to scan web ports on 10.x.x.x at 10kpps.\n", 6, 80);
    printf("\n");
    printf("  "XTATE_NAME" -p 80 -range 10.0.0.0/8 -scanmodule zbanner -probe getrequest\n");
    xprint("use ZBanner ScanModule to grab http banners with getrequest ProbeModule.\n", 6, 80);
    printf("\n");
    printf("  "XTATE_NAME" -p u:80 -range 10.0.0.0/8 -scanmodule udp-probe -probe echo -show fail\n");
    xprint("use UdpProbe ScanModule to scan UDP 80 port with echo ProbeModule and also show failed results.\n", 6, 80);
    printf("\n");
    printf("  "XTATE_NAME" -p s:38412 -range 10.0.0.0/8 -scanmodule sctp-init -show fail\n");
    xprint("use SctpInit ScanModule to scan SCTP 38412(36412) port and also show failed results.\n", 6, 80);
    printf("\n");
    printf("  "XTATE_NAME" -range 10.0.0.0/8 -scanmodule icmp-echo -timeout 6\n");
    xprint("use IcmpEcho ScanModule to do ping scan with a 6s timeout.\n", 6, 80);
    printf("\n");
    printf("  "XTATE_NAME" -range 192.168.0.1/24 -scanmodule arp-req -lan\n");
    xprint("do ARP scan with LAN mode in local network.\n", 6, 80);
    printf("\n");
    printf("  "XTATE_NAME" -range fe80::1/120 -scanmodule ndp-ns -src-ip fe80::2 -fake-router-mac\n");
    xprint("do NDP NS scan with a link-local source IP in local network.\n", 6, 80);
    printf("\n");
    printf("  "XTATE_NAME" -list-scan\n");
    xprint("list all ScanModules with introductions.\n", 6, 80);
    printf("\n");
    printf("  "XTATE_NAME" -list-probe\n");
    xprint("list all ProbeModules with introductions.\n", 6, 80);
    printf("\n");
    printf("  "XTATE_NAME" -list-output\n");
    xprint("list all OutputModules with introductions.\n", 6, 80);
    printf("\n");
    printf("  "XTATE_NAME" -version\n");
    xprint("print version and compilation info.\n", 6, 80);
    printf("\n");
    printf("  "XTATE_NAME" -usage\n");
    xprint("display this usage text of using examples.\n", 6, 80);
    printf("\n");
    printf("  "XTATE_NAME" -help\n");
    xprint("display detailed help text of all parameters.\n", 6, 80);
    printf("\n");
}

void xconf_print_version()
{
    const char *cpu = "unknown";
    const char *compiler = "unknown";
    const char *compiler_version = "unknown";
    const char *os = "unknown";
    printf("\n");
    printf("  "XTATE_FIRST_UPPER_NAME" version %s", XTATE_VERSION);
#ifdef NDEBUG
    printf(" in Release\n");
#else
    printf(" in Debug\n");
#endif
    printf("\n");
    printf("  Author : "XTATE_AUTHOR_NAME"\n");
    printf("  Github : "XTATE_GITHUB"\n");
    printf("  Contact: "XTATE_AUTHOR_MAIL"\n");
    printf("\n");
    printf("  Compiled on: %s %s\n", __DATE__, __TIME__);

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

        if (msc_ver < 1200)
            compiler_version = "pre6.0";
        else if (msc_ver == 1200)
            compiler_version = "6.0 VC++6.0";
        else if (msc_ver == 1300)
            compiler_version = ".NET 2002 VC++7.0";
        else if (msc_ver == 1310)
            compiler_version = ".NET 2003 VC++7.1";
        else if (msc_ver == 1400)
            compiler_version = "2005 VC++8.0";
        else if (msc_ver == 1500)
            compiler_version = "2008 VC++9.0";
        else if (msc_ver == 1600)
            compiler_version = "2010 VC++10.0";
        else if (msc_ver == 1700)
            compiler_version = "2012 VC++11.0";
        else if (msc_ver == 1800)
            compiler_version = "2013 VC++12.0";
        else if (msc_ver == 1900)
            compiler_version = "2015 VC++14.0";
        else if (msc_ver == 1910)
            compiler_version = "2017RTW VC++15.0";
        else if (msc_ver == 1911)
            compiler_version = "2017 VC++15.3";
        else if (msc_ver == 1912)
            compiler_version = "2017 VC++15.5";
        else if (msc_ver == 1913)
            compiler_version = "2017 VC++15.6";
        else if (msc_ver == 1914)
            compiler_version = "2017 VC++15.7";
        else if (msc_ver == 1915)
            compiler_version = "2017 VC++15.8";
        else if (msc_ver == 1916)
            compiler_version = "2017 VC++15.9";
        else if (msc_ver == 1920)
            compiler_version = "2019RTW VC++16.0";
        else if (msc_ver == 1921)
            compiler_version = "2019 VC++16.1";
        else if (msc_ver == 1922)
            compiler_version = "2019 VC++16.2";
        else if (msc_ver == 1923)
            compiler_version = "2019 VC++16.3";
        else if (msc_ver == 1924)
            compiler_version = "2019 VC++16.4";
        else if (msc_ver == 1925)
            compiler_version = "2019 VC++16.5";
        else if (msc_ver == 1926)
            compiler_version = "2019 VC++16.6";
        else if (msc_ver == 1927)
            compiler_version = "2019 VC++16.7";
        else if (msc_ver == 1928)
            compiler_version = "2019 VC++16.8/16.9a";
        else if (msc_ver == 1929)
            compiler_version = "2019 VC++16.10/16.11b";
        else if (msc_ver == 1930)
            compiler_version = "2022RTW VC++17.0";
        else if (msc_ver == 1931)
            compiler_version = "2022 VC++17.1";
        else if (msc_ver == 1932)
            compiler_version = "2022 VC++17.2";
        else if (msc_ver == 1933)
            compiler_version = "2022 VC++17.3";
        else if (msc_ver == 1934)
            compiler_version = "2022 VC++17.4";
        else if (msc_ver == 1935)
            compiler_version = "2022 VC++17.5";
        else if (msc_ver == 1936)
            compiler_version = "2022 VC++17.6";
        else if (msc_ver == 1937)
            compiler_version = "2022 VC++17.7";
        else if (msc_ver == 1938)
            compiler_version = "2022 VC++17.8";
        else if (msc_ver == 1939)
            compiler_version = "2022 VC++17.9";
        else if (msc_ver == 1940)
            compiler_version = "2022 VC++17.10";
        else
            compiler_version = "post-2022";
    }


#elif defined(__GNUC__)
# if defined(__clang__)
    compiler = "clang";
    compiler_version = __clang_version__;
# elif defined(__MINGW64__)
    compiler = "MinGW-w64 gcc";
    compiler_version = __VERSION__;
# elif defined(__MINGW32__)
    compiler = "MinGW-w32 gcc";
    compiler_version = __VERSION__;
# else
    compiler = "gcc";
    compiler_version = __VERSION__;
# endif

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

    printf("  Compiler: %s %s\n", compiler, compiler_version);
    printf("  OS: %s\n", os);
    printf("  CPU: %s (%u bits)\n", cpu, (unsigned)(sizeof(void*))*8);
    printf("\n");

    printf("  Build with libraries:\n");
    printf("    "OPENSSL_VERSION_TEXT"\n");

    char version[120];
    pcre2_config(PCRE2_CONFIG_VERSION, version);
    printf("    PCRE2  %s\n", version);

    printf("\n");
}

void xconf_print_help()
{
    printf("\n\n\n");
    xprint_with_head(ascii_xtate1, 15, 80);
    printf("\n                               "XTATE_GOD"\n\n");
    printf("\n");
    xprint("Welcome to "XTATE_FIRST_UPPER_NAME"!", 2, 80);
    printf("\n");
    xprint(XTATE_FOR, 4, 80);
    printf("\n");
    printf("\n");
    printf("  Author : "XTATE_AUTHOR_NAME"\n");
    printf("  Github : "XTATE_GITHUB"\n");
    printf("  Contact: "XTATE_AUTHOR_MAIL"\n");
    printf("\n");
    xprint("Here are detailed help text of all parameters of "
        XTATE_FIRST_UPPER_NAME". I hope these will help you a lot. If any "
        "problem or advice, please contact me.\n", 2, 80);
    printf("\n");
    printf("\n");
    printf("\n");

    unsigned count = 0;
    for (unsigned i=0; config_parameters[i].name; i++) {

        if (!config_parameters[i].helps) {
            if (config_parameters[i].set==&SET_nothing) {
                /*This is a paragraph name*/
                printf(XPRINT_EQUAL_LINE"\n");
                printf("  %s\n", config_parameters[i].name);
                printf(XPRINT_EQUAL_LINE"\n\n");
            }
            continue;
        }

        printf("  --%s", config_parameters[i].name);

        for (unsigned j=0; config_parameters[i].alts[j]; j++) {
            printf(", --%s", config_parameters[i].alts[j]);
        }

        printf("\n\n");
        xprint(config_parameters[i].helps, 6, 80);
        printf("\n\n\n");
        
        count++;
    }

    printf("\n\n");
    printf("   **************************************************************************\n");
    printf("   * Now contains [%d] parameters in total, use them to unleash your power! *\n", count);
    printf("   **************************************************************************\n");
    printf("\n\n\n");
}

void xconf_benchmark(unsigned blackrock_rounds)
{
    LOG(LEVEL_HINT, "=== benchmarking (%u-bits) ===\n\n", (unsigned)sizeof(void*)*8);
    blackrock_benchmark(blackrock_rounds);
    blackrock2_benchmark(blackrock_rounds);
    smack_benchmark();
}

/***************************************************************************
 ***************************************************************************/
static int xconf_self_selftest()
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
    LOG(LEVEL_ERROR, "[+] selftest failure: config subsystem\n");
    return 1;
}

void xconf_selftest()
{
    LOG(LEVEL_HINT, "Regression test: start...\n");

    int x = 0;

    //!Add new regression test here
    {
        x += massip_selftest();
        x += massip_parse_selftest();
        x += ipv6address_selftest();
        x += ranges_selftest();
        x += ranges6_selftest();
        x += rangesport_selftest();
        x += dedup_selftest();
        x += checksum_selftest();
        x += smack_selftest();
        x += blackrock_selftest();
        x += blackrock2_selftest();
        x += nmapservice_selftest();
        x += siphash24_selftest();
        x += lcg_selftest();
        x += pixie_time_selftest();
        x += rte_ring_selftest();
        x += xconf_self_selftest();
        x += rstfilter_selftest();
        x += base64_selftest();
        x += datachain_selftest();
        x += proto_http_maker_selftest();
        x += template_selftest();
    }

    if (x!=0)
        LOG(LEVEL_ERROR, "Regression test: failed :(\n");
    else
        LOG(LEVEL_HINT, "Regression test: success!\n");
}

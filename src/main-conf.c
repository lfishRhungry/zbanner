/*
    Read in the configuration for MASSCAN.

    Configuration parameters can be read either from the command-line
    or a configuration file. Long parameters of the --xxxx variety have
    the same name in both.

    Most of the code in this module is for 'nmap' options we don't support.
    That's because we support some 'nmap' options, and I wanted to give
    more feedback for some of them why they don't work as expected, such
    as reminding people that this is an asynchronous scanner.

*/
#include "masscan.h"
#include "massip/massip-addr.h"
#include "masscan-version.h"
#include "util/util-safefunc.h"
#include "util/util-logger.h"
#include "proto/proto-banner1.h"
#include "templ/templ-payloads.h"
#include "crypto/crypto-base64.h"
#include "vulncheck/vulncheck.h"
#include "proto/masscan-app.h"
#include "util/unusedparm.h"
#include "nmap-services/read-service-probes.h"
#include "util/util-malloc.h"
#include "massip/massip.h"
#include "massip/massip-addr.h"
#include "massip/massip-parse.h"
#include "massip/massip-port.h"
#include "templ/templ-opts.h"
#include <ctype.h>
#include <limits.h>

#ifdef WIN32
#include <direct.h>
#define getcwd _getcwd
#else
#include <unistd.h>
#endif

#ifndef min
#define min(a,b) ((a)<(b)?(a):(b))
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
masscan_save_state(struct Masscan *masscan)
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

    
    masscan_echo(masscan, fp, 0);

    fclose(fp);
}


#if 0
/*****************************************************************************
 * Read in ranges from a file
 *
 * There can be multiple ranges on a line, delimited by spaces. In fact,
 * millions of ranges can be on a line: there is limit to the line length.
 * That makes reading the file a little bit squirrelly. From one perspective
 * this parser doesn't treat the new-line '\n' any different than other
 * space. But, from another perspective, it has to, because things like
 * comments are terminated by a newline. Also, it has to count the number
 * of lines correctly to print error messages.
 *****************************************************************************/
static void
ranges_from_file(struct RangeList *ranges, const char *filename)
{
    FILE *fp;
    unsigned line_number = 0;

    fp = fopen(filename, "rt");
    if (fp) {
        perror(filename);
        exit(1); /* HARD EXIT: because if it's an exclusion file, we don't
                  * want to continue. We don't want ANY chance of
                  * accidentally scanning somebody */
    }

    while (!feof(fp)) {
        int c = '\n';

        /* remove leading whitespace */
        while (!feof(fp)) {
            c = getc(fp);
            line_number += (c == '\n');
            if (!isspace(c&0xFF))
                break;
        }

        /* If this is a punctuation, like '#', then it's a comment */
        if (ispunct(c&0xFF)) {
            while (!feof(fp)) {
                c = getc(fp);
                line_number += (c == '\n');
                if (c == '\n') {
                    break;
                }
            }
            /* Loop back to the begining state at the start of a line */
            continue;
        }

        if (c == '\n') {
            continue;
        }

        /*
         * Read in a single entry
         */
        if (!feof(fp)) {
            char address[64];
            size_t i;
            struct Range range;
            unsigned offset = 0;


            /* Grab all bytes until the next space or comma */
            address[0] = (char)c;
            i = 1;
            while (!feof(fp)) {
                c = getc(fp);
                if (c == EOF)
                    break;
                line_number += (c == '\n');
                if (isspace(c&0xFF) || c == ',') {
                    break;
                }
                if (i+1 >= sizeof(address)) {
                    LOG(0, "%s:%u:%u: bad address spec: \"%.*s\"\n",
                            filename, line_number, offset, (int)i, address);
                    exit(1);
                } else
                    address[i] = (char)c;
                i++;
            }
            address[i] = '\0';

            /* parse the address range */
            range = range_parse_ipv4(address, &offset, (unsigned)i);
            if (range.begin == 0xFFFFFFFF && range.end == 0) {
                LOG(0, "%s:%u:%u: bad range spec: \"%.*s\"\n",
                        filename, line_number, offset, (int)i, address);
                exit(1);
            } else {
                rangelist_add_range(ranges, range.begin, range.end);
            }
        }
    }

    fclose(fp);

    /* Target list must be sorted every time it's been changed, 
     * before it can be used */
    rangelist_sort(ranges);
}
#endif

/***************************************************************************
 ***************************************************************************/
static unsigned
hexval(char c)
{
    if ('0' <= c && c <= '9')
        return (unsigned)(c - '0');
    if ('a' <= c && c <= 'f')
        return (unsigned)(c - 'a' + 10);
    if ('A' <= c && c <= 'F')
        return (unsigned)(c - 'A' + 10);
    return 0xFF;
}

/***************************************************************************
 ***************************************************************************/
static int
parse_mac_address(const char *text, macaddress_t *mac)
{
    unsigned i;

    for (i=0; i<6; i++) {
        unsigned x;
        char c;

        while (isspace(*text & 0xFF) && ispunct(*text & 0xFF))
            text++;

        c = *text;
        if (!isxdigit(c&0xFF))
            return -1;
        x = hexval(c)<<4;
        text++;

        c = *text;
        if (!isxdigit(c&0xFF))
            return -1;
        x |= hexval(c);
        text++;

        mac->addr[i] = (unsigned char)x;

        if (ispunct(*text & 0xFF))
            text++;
    }

    return 0;
}

/***************************************************************************
 ***************************************************************************/
static uint64_t
parseInt(const char *str)
{
    uint64_t result = 0;

    while (*str && isdigit(*str & 0xFF)) {
        result = result * 10 + (*str - '0');
        str++;
    }
    return result;
}

/**
 * a stricter function for determining if something is boolean.
 */
static bool
isBoolean(const char *str) {
    size_t length = str?strlen(str):0;

    if (length == 0)
        return false;

    /* "0" or "1" is boolean */
    if (isdigit(str[0])) {
        if (strtoul(str,0,0) == 0)
            return true;
        else if (strtoul(str,0,0) == 1)
            return true;
        else
            return false;
    }

    switch (str[0]) {
        case 'e':
        case 'E':
            if (memcasecmp("enable", str, length)==0)
                return true;
            if (memcasecmp("enabled", str, length)==0)
                return true;
            return false;
        case 'd':
        case 'D':
            if (memcasecmp("disable", str, length)==0)
                return true;
            if (memcasecmp("disabled", str, length)==0)
                return true;
            return false;

        case 't':
        case 'T':
            if (memcasecmp("true", str, length)==0)
                return true;
            return false;
        case 'f':
        case 'F':
            if (memcasecmp("false", str, length)==0)
                return true;
            return false;

        case 'o':
        case 'O':
            if (memcasecmp("on", str, length)==0)
                return true;
            if (memcasecmp("off", str, length)==0)
                return true;
            return false;
        case 'Y':
        case 'y':
            if (memcasecmp("yes", str, length)==0)
                return true;
            return false;
        case 'n':
        case 'N':
            if (memcasecmp("no", str, length)==0)
                return true;
            return false;
        default:
            return false;
    }
}

static unsigned
parseBoolean(const char *str)
{
    if (str == NULL || str[0] == 0)
        return 1;
    if (isdigit(str[0])) {
        if (strtoul(str,0,0) == 0)
            return 0;
        else
            return 1;
    }
    switch (str[0]) {
    case 'e': /* enable */
    case 'E':
        return 1;
    case 'd': /* disable */
    case 'D':
        return 0;

    case 't': /* true */
    case 'T':
        return 1;
    case 'f': /* false */
    case 'F':
        return 0;

    case 'o': /* on or off */
    case 'O':
        if (str[1] == 'f' || str[1] == 'F')
            return 0;
        else
            return 1;
        break;

    case 'Y': /* yes */
    case 'y':
        return 1;
    case 'n': /* no */
    case 'N':
        return 0;
    }
    return 1;
}

/***************************************************************************
 * Parses the number of seconds (for rotating files mostly). We do a little
 * more than just parse an integer. We support strings like:
 *
 * hourly
 * daily
 * Week
 * 5days
 * 10-months
 * 3600
 ***************************************************************************/
static uint64_t
parseTime(const char *value)
{
    uint64_t num = 0;
    unsigned is_negative = 0;

    while (*value == '-') {
        is_negative = 1;
        value++;
    }

    while (isdigit(value[0]&0xFF)) {
        num = num*10 + (value[0] - '0');
        value++;
    }
    while (ispunct(value[0]) || isspace(value[0]))
        value++;

    if (isalpha(value[0]) && num == 0)
        num = 1;

    if (value[0] == '\0')
        return num;

    switch (tolower(value[0])) {
    case 's':
        num *= 1;
        break;
    case 'm':
        num *= 60;
        break;
    case 'h':
        num *= 60*60;
        break;
    case 'd':
        num *= 24*60*60;
        break;
    case 'w':
        num *= 24*60*60*7;
        break;
    default:
        fprintf(stderr, "--rotate-offset: unknown character\n");
        exit(1);
    }
    if (num >= 24*60*60) {
        fprintf(stderr, "--rotate-offset: value is greater than 1 day\n");
        exit(1);
    }
    if (is_negative)
        num = 24*60*60 - num;

    return num;
}

/***************************************************************************
 * Parses a size integer, which can be suffixed with "tera", "giga", 
 * "mega", and "kilo". These numbers are in units of 1024 so suck it.
 ***************************************************************************/
static uint64_t
parseSize(const char *value)
{
    uint64_t num = 0;

    while (isdigit(value[0]&0xFF)) {
        num = num*10 + (value[0] - '0');
        value++;
    }
    while (ispunct(value[0]) || isspace(value[0]))
        value++;

    if (isalpha(value[0]) && num == 0)
        num = 1;

    if (value[0] == '\0')
        return num;

    switch (tolower(value[0])) {
    case 'k': /* kilobyte */
        num *= 1024ULL;
        break;
    case 'm': /* megabyte */
        num *= 1024ULL * 1024ULL;
        break;
    case 'g': /* gigabyte */
        num *= 1024ULL * 1024ULL * 1024ULL;
        break;
    case 't': /* terabyte, 'cause we roll that way */
        num *=  1024ULL * 1024ULL * 1024ULL * 1024ULL;
        break;
    case 'p': /* petabyte, 'cause we are awesome */
        num *=  1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
        break;
    case 'e': /* exabyte, now that's just silly */
        num *=  1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
        break;
    default:
        fprintf(stderr, "--rotate-size: unknown character\n");
        exit(1);
    }
    return num;
}


/***************************************************************************
 ***************************************************************************/
static int
is_power_of_two(uint64_t x)
{
    while ((x&1) == 0)
        x >>= 1;
    return x == 1;
}


/***************************************************************************
 * Tests if the named parameter on the command-line. We do a little
 * more than a straight string compare, because I get confused
 * whether parameter have punctuation. Is it "--excludefile" or
 * "--exclude-file"? I don't know if it's got that dash. Screw it,
 * I'll just make the code so it don't care.
 ***************************************************************************/
static int
EQUALS(const char *lhs, const char *rhs)
{
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return 1; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return 0;
        if (*lhs == '\0')
            return 1;
        lhs++;
        rhs++;
    }
}

static int
EQUALSx(const char *lhs, const char *rhs, size_t rhs_length)
{
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return 1; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return 0;
        if (*lhs == '\0')
            return 1;
        lhs++;
        rhs++;
        if (--rhs_length == 0)
            return 1;
    }
}

static unsigned
INDEX_OF(const char *str, char c)
{
    unsigned i;
    for (i=0; str[i] && str[i] != c; i++)
        ;
    return i;
}

static unsigned
ARRAY(const char *rhs)
{
    const char *p = strchr(rhs, '[');
    if (p == NULL)
        return 0;
    else
        p++;
    return (unsigned)parseInt(p);
}

/**
 * Called if user specified `--top-ports` on the command-line.
 */
static void
config_top_ports(struct Masscan *masscan, unsigned maxports)
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
    struct RangeList *ports = &masscan->targets.ports;
    static const unsigned max_tcp_ports = sizeof(top_tcp_ports)/sizeof(top_tcp_ports[0]);
    static const unsigned max_udp_ports = sizeof(top_udp_ports)/sizeof(top_udp_ports[0]);


    if (masscan->scan_type.tcp) {
        LOG(2, "[+] adding TCP top-ports = %u\n", maxports);
        for (i=0; i<maxports && i<max_tcp_ports; i++)
            rangelist_add_range_tcp(ports,
                                top_tcp_ports[i],
                                top_tcp_ports[i]);
    }

    if (masscan->scan_type.udp) {
        LOG(2, "[+] adding UDP top-ports = %u\n", maxports);
        for (i=0; i<maxports && i<max_udp_ports; i++)
            rangelist_add_range_udp(ports,
                                top_udp_ports[i],
                                top_udp_ports[i]);
    }

    /* Targets must be sorted after every change, before being used */
    rangelist_sort(ports);
}

/***************************************************************************
 ***************************************************************************/
static int
isInteger(const char *value)
{
    size_t i;
    
    if (value == NULL)
        return 0;
    
    for (i=0; value[i]; i++)
        if (!isdigit(value[i]&0xFF))
            return 0;
    return 1;
}

/***************************************************************************
 ***************************************************************************/
typedef int (*SET_PARAMETER)(struct Masscan *masscan, const char *name, const char *value);
enum {CONF_OK, CONF_WARN, CONF_ERR};

static int SET_stateless_banners(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->is_stateless_banners || masscan->echo_all)
            fprintf(masscan->echo, "stateless-banners = %s\n", masscan->is_stateless_banners?"true":"false");
       return 0;
    }
    masscan->is_stateless_banners = parseBoolean(value);

    if (masscan->is_banners && masscan->is_stateless_banners) {
        fprintf(stderr, "FAIL %s: can not specify banners mode and stateless-banners mode at the same time.\n", name);
        fprintf(stderr, "Hint: banners mode gets banners with TCP\\IP stack in user mode.\n");
        fprintf(stderr, "Hint: stateless-banners mode gets banners in stateless. \n");
        return CONF_ERR;
    }

    return CONF_OK;
}

static int SET_stateless_probe(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->stateless_probe){
            fprintf(masscan->echo, "stateless-probe = %s\n", masscan->stateless_probe->name);
        }
        return 0;
    }

    if(!masscan->is_stateless_banners){
        fprintf(stderr, "FAIL %s: use --stateless-banners mode before specify %s\n", value, name);
        return CONF_ERR;
    }

    masscan->stateless_probe = get_stateless_probe(value);
    if(!masscan->stateless_probe){
        fprintf(stderr, "FAIL %s: no such stateless probe\n", value);
        return CONF_ERR;
    }

    return CONF_OK;
}

static int SET_probe_args(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->stateless_probe){
            fprintf(masscan->echo, "stateless-probe = %s\n", masscan->stateless_probe->name);
        }
        return 0;
    }

    
    unsigned value_len = strlen(value);
    if (value_len >= STATELESS_PROBE_ARGS_LEN) {
        fprintf(stderr, "FAIL %s: length of value is too long\n", name);
        fprintf(stderr, "Hint: length of %s value must be no more than %u.\n",
            name, STATELESS_PROBE_ARGS_LEN-1);
        return CONF_ERR;
    }

	memcpy(masscan->stateless_probe_args, value, value_len);
    return CONF_OK;
}

/**
 * It's not good enough to set --list-probes this way because possibly conflict
 * with other parameter. Only using --list-probes would be no problem if want to
 * list probes. 
*/
static int SET_list_probes(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
       return 0;
    }
    masscan->op = parseBoolean(value)?Operation_List_Probes:masscan->op;
    return CONF_OK;
}

static int SET_iflist(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (masscan->echo) {
        if (masscan->op==Operation_ReadRange || masscan->echo_all)
            fprintf(masscan->echo, "iflist = %s\n",
                masscan->op==Operation_List_Adapters?"true":"false");
        return 0;
    }

    if (parseBoolean(value))
        masscan->op = Operation_List_Adapters;
    return CONF_OK;
}

static int SET_benchmark(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (masscan->echo) {
        if (masscan->op==Operation_Benchmark || masscan->echo_all)
            fprintf(masscan->echo, "benchmark = %s\n",
                masscan->op==Operation_Benchmark?"true":"false");
        return 0;
    }

    if (parseBoolean(value))
        masscan->op = Operation_Benchmark;

    return CONF_OK;
}

static int SET_selftest(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (masscan->echo) {
        if (masscan->op==Operation_Selftest || masscan->echo_all)
            fprintf(masscan->echo, "selftest = %s\n",
                masscan->op==Operation_Selftest?"true":"false");
        return 0;
    }

    if (parseBoolean(value))
        masscan->op = Operation_Selftest;

    return CONF_OK;
}

static int SET_read_scan(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);

    if (masscan->echo) {
        if (masscan->op==Operation_ReadRange || masscan->echo_all)
            fprintf(masscan->echo, "read-range = %s\n",
                masscan->op==Operation_ReadRange?"true":"false");
        return 0;
    }

    /* Read in a binary file instead of scanning the network*/
    masscan->op = Operation_ReadScan;
    
    /* Default to reading banners */
    masscan->is_banners = true;
    masscan->is_banners_rawudp = true;

    return CONF_OK;
}

static int SET_read_range(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (masscan->echo) {
        if (masscan->op==Operation_ReadRange || masscan->echo_all)
            fprintf(masscan->echo, "read-range = %s\n",
                masscan->op==Operation_ReadRange?"true":"false");
        return 0;
    }

    if (parseBoolean(value))
        masscan->op = Operation_ReadRange;

    return CONF_OK;
}

static int SET_pfring(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (masscan->echo) {
        if (masscan->is_pfring || masscan->echo_all)
            fprintf(masscan->echo, "pfring = %s\n", masscan->is_pfring?"true":"false");
        return 0;
    }

    masscan->is_pfring = parseBoolean(value);

    return CONF_OK;
}

/**
 * See proto-oproto.h
 * oproto does nothing now
 * */
static int SET_oproto(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (masscan->echo) {
        if (masscan->scan_type.oproto || masscan->echo_all)
            fprintf(masscan->echo, "oproto = %s\n",
                masscan->scan_type.oproto?"true":"false");
        return 0;
    }

    unsigned is_error = 0;
    masscan->scan_type.oproto = 1;
    rangelist_parse_ports(&masscan->targets.ports, value, &is_error, Templ_Oproto_first);
    if (masscan->op == 0)
        masscan->op = Operation_Scan;

    return CONF_OK;
}

static int SET_ping(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (masscan->echo) {
        if (masscan->scan_type.ping || masscan->echo_all)
            fprintf(masscan->echo, "ping = %s\n", masscan->scan_type.ping?"true":"false");
        return 0;
    }

    /* Add ICMP ping request */
    struct Range range;
    range.begin = Templ_ICMP_echo;
    range.end = Templ_ICMP_echo;
    rangelist_add_range(&masscan->targets.ports, range.begin, range.end);
    rangelist_sort(&masscan->targets.ports);
    masscan->scan_type.ping = 1;

    return CONF_OK;
}

static int SET_arpscan(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (masscan->echo) {
        if (masscan->scan_type.arp || masscan->echo_all)
            fprintf(masscan->echo, "arpscan = %s\n", masscan->scan_type.arp?"true":"false");
        return 0;
    }

    struct Range range;

    if (parseBoolean(value)) {
        range.begin = Templ_ARP;
        range.end = Templ_ARP;
        rangelist_add_range(&masscan->targets.ports, range.begin, range.end);
        rangelist_sort(&masscan->targets.ports);
        masscan_set_parameter(masscan, "router-mac", "ff-ff-ff-ff-ff-ff");
        masscan->scan_type.arp = 1;
    }

    return CONF_OK;
}

static int SET_banners(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->is_banners || masscan->echo_all)
            fprintf(masscan->echo, "banners = %s\n", masscan->is_banners?"true":"false");
       return 0;
    }
    masscan->is_banners = parseBoolean(value);

    if (masscan->is_banners && masscan->is_stateless_banners) {
        fprintf(stderr, "FAIL %s: can not specify banners mode and stateless-banners mode at the same time.\n", name);
        fprintf(stderr, "Hint: banners mode gets banners with TCP\\IP stack in user mode.\n");
        fprintf(stderr, "Hint: stateless-banners mode gets banners in stateless. \n");
        return CONF_ERR;
    }

    return CONF_OK;
}

static int SET_nodedup(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->is_nodedup1 || masscan->echo_all) {
            fprintf(masscan->echo, "nodedup1 = %s\n", masscan->is_nodedup1?"true":"false");
        }
        if (masscan->is_nodedup2 || masscan->echo_all) {
            fprintf(masscan->echo, "nodedup2 = %s\n", masscan->is_nodedup2?"true":"false");
        }
       return 0;
    }

    if (EQUALS(name, "nodedup1"))
        masscan->is_nodedup1 = parseBoolean(value);
    else if (EQUALS(name, "nodedup2"))
        masscan->is_nodedup2 = parseBoolean(value);
    else if (EQUALS(name, "nodedup")) {
        masscan->is_nodedup1 = parseBoolean(value);
        masscan->is_nodedup2 = parseBoolean(value);
    }

    return CONF_OK;
}

static int SET_badsum(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->nmap.badsum || masscan->echo_all)
            fprintf(masscan->echo, "badsum = %s\n", masscan->nmap.badsum?"true":"false");
       return 0;
    }

    masscan->nmap.badsum = parseBoolean(value);

    return CONF_OK;
}

static int SET_ttl(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->nmap.ttl || masscan->echo_all)
            fprintf(masscan->echo, "ttl = %u\n", masscan->nmap.ttl);
       return 0;
    }

    unsigned x = parseInt(value);
    if (x >= 256) {
        fprintf(stderr, "error: %s=<n>: expected number less than 256\n", name);
        return CONF_ERR;
    } else {
        masscan->nmap.ttl = x;
    }

    return CONF_OK;
}

static int SET_dedup_win(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->dedup_win1!=1000000 || masscan->echo_all)
            fprintf(masscan->echo, "dedup-win1 = %u\n", masscan->dedup_win1);
        if (masscan->dedup_win2!=1000000 || masscan->echo_all)
            fprintf(masscan->echo, "dedup-win2 = %u\n", masscan->dedup_win2);
       return 0;
    }

    if (parseInt(value)<=0) {
        fprintf(stderr, "FAIL: %s: dedup-win must > 0.\n", name);
        return CONF_ERR;
    }

    if (EQUALS(name, "dedupwin1") || EQUALS(name, "dedup-win1"))
        masscan->dedup_win1 = parseInt(value);
    else if (EQUALS(name, "dedupwin2") || EQUALS(name, "dedup-win2"))
        masscan->dedup_win2 = parseInt(value);
    else if (EQUALS(name, "dedupwin") || EQUALS(name, "dedup-win")) {
        masscan->dedup_win1 = parseInt(value);
        masscan->dedup_win2 = parseInt(value);
    }

    return CONF_OK;
}

static int SET_feed_lzr(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->output.is_feed_lzr || masscan->echo_all)
            fprintf(masscan->echo, "feed-lzr = %s\n", masscan->output.is_feed_lzr?"true":"false");
       return 0;
    }
    masscan->output.is_feed_lzr = parseBoolean(value);
    return CONF_OK;
}

static int SET_stack_buf_count(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->stack_buf_count!=16384 || masscan->echo_all) {
            fprintf(masscan->echo, "stack-buf-count = %u\n", masscan->stack_buf_count);
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

    masscan->stack_buf_count = v;

    return CONF_OK;
}

static int SET_wait(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->wait==INT_MAX)
            fprintf(masscan->echo, "wait = forever\n");
        else
            fprintf(masscan->echo, "wait = %u\n", masscan->wait);
        return 0;
    }

    if (EQUALS("forever", value))
        masscan->wait =  INT_MAX;
    else
        masscan->wait = (unsigned)parseInt(value);

    return CONF_OK;
}

static int SET_thread_count(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        fprintf(masscan->echo, "transmit-thread-count = %u\n", masscan->tx_thread_count);
        fprintf(masscan->echo, "receive-thread-count  = 1 (always)\n");
        return 0;
    }

    unsigned count = parseInt(value);
    if (count==0) {
        fprintf(stderr, "FAIL: %s: transmit thread count cannot be zero.\n", name);
        return CONF_ERR;
    }

    masscan->tx_thread_count = count;

    return CONF_OK;
}

static int SET_debug_interface(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->op==Operation_DebugIF || masscan->echo_all)
            fprintf(masscan->echo, "debug interface = %s\n",
                masscan->op==Operation_DebugIF?"true":"false");
       return 0;
    }
    if (parseBoolean(value))
        masscan->op = Operation_DebugIF;
    return CONF_OK;
}

static int SET_conn_timeout(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->tcp_connection_timeout || masscan->echo_all)
            fprintf(masscan->echo, "connection-timeout = %u\n",
                masscan->tcp_connection_timeout);
       return 0;
    }

    masscan->tcp_connection_timeout = parseInt(value);

    return CONF_OK;
}

static int SET_banners_rawudp(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->is_banners_rawudp || masscan->echo_all)
            fprintf(masscan->echo, "rawudp = %s\n", masscan->is_banners_rawudp?"true":"false");
       return 0;
    }
    masscan->is_banners_rawudp = parseBoolean(value);
    if (masscan->is_banners_rawudp)
        masscan->is_banners = true;

    if (masscan->is_banners && masscan->is_stateless_banners) {
        fprintf(stderr, "FAIL %s: can not specify banners mode and stateless-banners mode at the same time.\n", name);
        fprintf(stderr, "Hint: banners mode gets banners with TCP\\IP stack in user mode.\n");
        fprintf(stderr, "Hint: stateless-banners mode gets banners in stateless. \n");
        return CONF_ERR;
    }

    return CONF_OK;
}

static int SET_capture(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (!masscan->is_capture_cert || masscan->echo_all)
            fprintf(masscan->echo, "%scapture = cert\n", masscan->is_capture_cert?"":"no");
        if (!masscan->is_capture_servername || masscan->echo_all)
            fprintf(masscan->echo, "%scapture = servername\n", masscan->is_capture_servername?"":"no");
        if (masscan->is_capture_html || masscan->echo_all)
            fprintf(masscan->echo, "%scapture = html\n", masscan->is_capture_html?"":"no");
        if (masscan->is_capture_heartbleed || masscan->echo_all)
            fprintf(masscan->echo, "%scapture = heartbleed\n", masscan->is_capture_heartbleed?"":"no");
        if (masscan->is_capture_ticketbleed || masscan->echo_all)
            fprintf(masscan->echo, "%scapture = ticketbleed\n", masscan->is_capture_ticketbleed?"":"no");
        if (masscan->is_capture_stateless || masscan->echo_all)
            fprintf(masscan->echo, "%scapture = stateless\n", masscan->is_capture_stateless?"":"no");
        return 0;
    }
    if (EQUALS("capture", name)) {
        if (EQUALS("cert", value))
            masscan->is_capture_cert = 1;
        else if (EQUALS("servername", value))
            masscan->is_capture_servername = 1;
        else if (EQUALS("html", value))
            masscan->is_capture_html = 1;
        else if (EQUALS("heartbleed", value))
            masscan->is_capture_heartbleed = 1;
        else if (EQUALS("ticketbleed", value))
            masscan->is_capture_ticketbleed = 1;
        else if (EQUALS("stateless", value))
            masscan->is_capture_stateless = 1;
        else {
            fprintf(stderr, "FAIL: %s: unknown capture type\n", value);
            return CONF_ERR;
        }
    } else if (EQUALS("nocapture", name)) {
        if (EQUALS("cert", value))
            masscan->is_capture_cert = 0;
        else if (EQUALS("servername", value))
            masscan->is_capture_servername = 0;
        else if (EQUALS("html", value))
            masscan->is_capture_html = 0;
        else if (EQUALS("heartbleed", value))
            masscan->is_capture_heartbleed = 0;
        else if (EQUALS("ticketbleed", value))
            masscan->is_capture_ticketbleed = 0;
        else if (EQUALS("stateless", value))
            masscan->is_capture_stateless = 0;
        else {
            fprintf(stderr, "FAIL: %s: unknown nocapture type\n", value);
            return CONF_ERR;
        }
    }
    return CONF_OK;
}

static int SET_banner_type(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->banner_types.count > 0) {
            fprintf(masscan->echo, "banner types =");
            /*Actually, only one type will be print*/
            for (unsigned i=0; i<masscan->banner_types.count; i++) {
                fprintf(masscan->echo, " %s",
                    masscan_app_to_string(masscan->banner_types.list[i].begin));
            }
            fprintf(masscan->echo, "\n");
        }
        return 0;
    }

    /*It may only add one type*/
    enum ApplicationProtocol app;
    app = masscan_string_to_app(value);
    
    if (app) {
        rangelist_add_range(&masscan->banner_types, app, app);
        rangelist_sort(&masscan->banner_types);
    } else {
        fprintf(stderr, "FAIL: bad banner app: %s\n", value);
        return CONF_ERR;
    }

    return CONF_OK;
}

static int SET_hello(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->is_hello_ssl) {
            fprintf(masscan->echo, "hello = ssl\n");
        } else if (masscan->is_hello_smbv1) {
            fprintf(masscan->echo, "hello = smbv1\n");
        } else if (masscan->is_hello_http) {
            fprintf(masscan->echo, "hello = http\n");
        }
        return 0;
    }
    if (EQUALS("ssl", value))
        masscan->is_hello_ssl = 1;
    else if (EQUALS("smbv1", value))
        masscan->is_hello_smbv1 = 1;
    else if (EQUALS("http", value))
        masscan->is_hello_http = 1;
    else {
        fprintf(stderr, "FAIL: %s: unknown hello type\n", value);
        return CONF_ERR;
    }
    return CONF_OK;
}

static int SET_adapter(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->nic.ifname[0] || masscan->echo_all) {
            fprintf(masscan->echo, "adapter = %s\n", masscan->nic.ifname);
        }
        return 0;
    }

    if (masscan->nic.ifname[0]) {
        fprintf(stderr, "CONF: overwriting \"adapter=%s\"\n", masscan->nic.ifname);
    }
    snprintf(  masscan->nic.ifname, sizeof(masscan->nic.ifname),
        "%s", value);

    return CONF_OK;
}

static int SET_source_ip(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {

        if (masscan->nic.src.ipv4.first) {
            ipaddress_formatted_t ipv4_first =
                ipv4address_fmt((ipv4address)(masscan->nic.src.ipv4.first));
            ipaddress_formatted_t ipv4_last =
                ipv4address_fmt((ipv4address)(masscan->nic.src.ipv4.last));
            fprintf(masscan->echo, "source IPv4 first = %s\n", ipv4_first.string);
            fprintf(masscan->echo, "source IPv4 last = %s\n", ipv4_last.string);
            fprintf(masscan->echo, "source IPv4 range = %u\n", masscan->nic.src.ipv4.range);
        }

        if (masscan->nic.src.ipv6.first.hi && masscan->nic.src.ipv6.first.lo) {
            ipaddress_formatted_t ipv6_first =
                ipv6address_fmt((ipv6address)(masscan->nic.src.ipv6.first));
            ipaddress_formatted_t ipv6_last =
                ipv6address_fmt((ipv6address)(masscan->nic.src.ipv6.last));
            fprintf(masscan->echo, "source IPv6 first = %s\n", ipv6_first.string);
            fprintf(masscan->echo, "source IPv6 last = %s\n", ipv6_last.string);
            fprintf(masscan->echo, "source IPv6 range = %u\n", masscan->nic.src.ipv6.range);
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
            masscan->nic.src.ipv4.first = range.begin;
            masscan->nic.src.ipv4.last = range.end;
            masscan->nic.src.ipv4.range = range.end - range.begin + 1;
            break;
        case Ipv6_Address:
            masscan->nic.src.ipv6.first = range6.begin;
            masscan->nic.src.ipv6.last = range6.end;
            masscan->nic.src.ipv6.range = 1; /* TODO: add support for more than one source */
            break;
        default:
            fprintf(stderr, "FAIL: bad source IP address: %s=%s\n",
                name, value);
            fprintf(stderr, "hint   addresses look like \"192.168.1.23\" or \"2001:db8:1::1ce9\".\n");
            return CONF_ERR;
    }

    return CONF_OK;
}

static int SET_source_port(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->nic.src.port.first) {
            fprintf(masscan->echo, "source port first = %u\n", masscan->nic.src.port.first);
            fprintf(masscan->echo, "source port last = %u\n", masscan->nic.src.port.last);
            fprintf(masscan->echo, "source port range = %u\n", masscan->nic.src.port.range);
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

    masscan->nic.src.port.first = ports.list[0].begin;
    masscan->nic.src.port.last = ports.list[0].end;
    masscan->nic.src.port.range = ports.list[0].end - ports.list[0].begin + 1;

    return CONF_OK;
}

static int SET_target_output(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        fprintf(masscan->echo, "ports = ");
        /* Disable comma generation for the first element */
        unsigned i;
        unsigned l = 0;
        l = 0;
        for (i=0; i<masscan->targets.ports.count; i++) {
            struct Range range = masscan->targets.ports.list[i];
            do {
                struct Range rrange = range;
                unsigned done = 0;
                if (l)
                    fprintf(masscan->echo, ",");
                l = 1;
                if (rrange.begin >= Templ_ICMP_echo) {
                    rrange.begin -= Templ_ICMP_echo;
                    rrange.end -= Templ_ICMP_echo;
                    fprintf(masscan->echo,"I:");
                    done = 1;
                } else if (rrange.begin >= Templ_SCTP) {
                    rrange.begin -= Templ_SCTP;
                    rrange.end -= Templ_SCTP;
                    fprintf(masscan->echo,"S:");
                    range.begin = Templ_ICMP_echo;
                } else if (rrange.begin >= Templ_UDP) {
                    rrange.begin -= Templ_UDP;
                    rrange.end -= Templ_UDP;
                    fprintf(masscan->echo,"U:");
                    range.begin = Templ_SCTP;
                } else if (Templ_Oproto_first <= rrange.begin && rrange.begin <= Templ_Oproto_last) {
                    rrange.begin -= Templ_Oproto_first;
                    rrange.end -= Templ_Oproto_first;
                    fprintf(masscan->echo, "O:");
                    range.begin = Templ_Oproto_first;
                } else
                    range.begin = Templ_UDP;
                rrange.end = min(rrange.end, 65535);
                if (rrange.begin == rrange.end)
                    fprintf(masscan->echo, "%u", rrange.begin);
                else
                    fprintf(masscan->echo, "%u-%u", rrange.begin, rrange.end);
                if (done)
                    break;
            } while (range.begin <= range.end);
        }
        fprintf(masscan->echo, "\n");
        /*
        * IPv4 address targets
        */
        for (i=0; i<masscan->targets.ipv4.count; i++) {
            unsigned prefix_bits;
            struct Range range = masscan->targets.ipv4.list[i];

            if (range.begin == range.end) {
                fprintf(masscan->echo, "range = %u.%u.%u.%u",
                        (range.begin>>24)&0xFF,
                        (range.begin>>16)&0xFF,
                        (range.begin>> 8)&0xFF,
                        (range.begin>> 0)&0xFF
                        );
            } else if (range_is_cidr(range, &prefix_bits)) {
                fprintf(masscan->echo, "range = %u.%u.%u.%u/%u",
                        (range.begin>>24)&0xFF,
                        (range.begin>>16)&0xFF,
                        (range.begin>> 8)&0xFF,
                        (range.begin>> 0)&0xFF,
                        prefix_bits
                        );

            } else {
                fprintf(masscan->echo, "range = %u.%u.%u.%u-%u.%u.%u.%u",
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
            fprintf(masscan->echo, "\n");
        }
        for (i=0; i<masscan->targets.ipv6.count; i++) {
            bool exact = false;
            struct Range6 range = masscan->targets.ipv6.list[i];
            ipaddress_formatted_t fmt = ipv6address_fmt(range.begin);
            
            fprintf(masscan->echo, "range = %s", fmt.string);
            if (!ipv6address_is_equal(range.begin, range.end)) {
                unsigned cidr_bits = count_cidr6_bits(&range, &exact);
                
                if (exact && cidr_bits) {
                    fprintf(masscan->echo, "/%u", cidr_bits);
                } else {
                    fmt = ipv6address_fmt(range.end);
                    fprintf(masscan->echo, "-%s", fmt.string);
                }
            }
            fprintf(masscan->echo, "\n");
        }
    }

    return CONF_OK;
}

static int SET_target_ip(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        /*echo in SET_target_output*/
        return 0;
    }
    
    int err;
    err = massip_add_target_string(&masscan->targets, value);
    if (err) {
        fprintf(stderr, "ERROR: bad IP address/range: %s\n", value);
        return CONF_ERR;
    }

    if (masscan->op == 0)
        masscan->op = Operation_Scan;

    return CONF_OK;
}

static int SET_adapter_vlan(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->nic.is_vlan || masscan->echo_all) {
            if (masscan->nic.is_vlan)
                fprintf(masscan->echo, "vlan id = %u\n", masscan->nic.vlan_id);
            else
                fprintf(masscan->echo, "use vlan = false\n");
        }
        return 0;
    }
    
    masscan->nic.is_vlan = 1;
    masscan->nic.vlan_id = (unsigned)parseInt(value);

    return CONF_OK;
}

static int SET_target_port(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        /*echo in SET_target_output*/
        return 0;
    }
    
    unsigned is_error = 0;
    int err = 0;

    if (name[0]=='t') {
        masscan->scan_type.tcp = 1;
        rangelist_parse_ports(&masscan->targets.ports, value, &is_error, Templ_TCP);
    } else if (name[0]=='u') {
        masscan->scan_type.udp = 1;
        rangelist_parse_ports(&masscan->targets.ports, value, &is_error, Templ_UDP);
    } else {
        unsigned defaultrange = 0;

        if (masscan->scan_type.udp)
            defaultrange = Templ_UDP;
        else if (masscan->scan_type.sctp)
            defaultrange = Templ_SCTP;
        
        err = massip_add_port_string(&masscan->targets, value, defaultrange);
    }

    if (is_error || err) {
        fprintf(stderr, "[-] FAIL: bad target port: %s\n", value);
        fprintf(stderr, "    Hint: a port is a number [0..65535]\n");
        return CONF_ERR;
    }

    if (masscan->op == 0)
        masscan->op = Operation_Scan;

    return CONF_OK;
}

static int SET_exclude_ip(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    int err;
    err = massip_add_target_string(&masscan->exclude, value);
    if (err) {
        fprintf(stderr, "ERROR: bad exclude address/range: %s\n", value);
        return CONF_ERR;
    }

    if (masscan->op == 0)
        masscan->op = Operation_Scan;
    
    return CONF_OK;
}

static int SET_exclude_port(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        /*echo in SET_target_output*/
        return 0;
    }
    unsigned defaultrange = 0;
    int err;

    if (masscan->scan_type.udp)
        defaultrange = Templ_UDP;
    else if (masscan->scan_type.sctp)
        defaultrange = Templ_SCTP;
    
    err = massip_add_port_string(&masscan->exclude, value, defaultrange);
    if (err) {
        fprintf(stderr, "[-] FAIL: bad exclude port: %s\n", value);
        fprintf(stderr, "    Hint: a port is a number [0..65535]\n");
        return CONF_ERR;
    }
    if (masscan->op == 0)
        masscan->op = Operation_Scan;
    
    return CONF_OK;
}

static int SET_include_file(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    int err;
    const char *filename = value;

    err = massip_parse_file(&masscan->targets, filename);
    if (err) {
        fprintf(stderr, "[-] FAIL: error reading from include file\n");
        return CONF_ERR;
    }
    if (masscan->op == 0)
        masscan->op = Operation_Scan;
    
    return CONF_OK;
}

static int SET_exclude_file(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    unsigned count1 = masscan->exclude.ipv4.count;
    unsigned count2;
    int err;
    const char *filename = value;

    // LOG(1, "EXCLUDING: %s\n", value);
    err = massip_parse_file(&masscan->exclude, filename);
    if (err) {
        fprintf(stderr, "[-] FAIL: error reading from exclude file\n");
        return CONF_ERR;
    }
    /* Detect if this file has made any change, otherwise don't print
        * a message */
    count2 = masscan->exclude.ipv4.count;
    if (count2 - count1)
        fprintf(stderr, "%s: excluding %u ranges from file\n",
            value, count2 - count1);
    
    return CONF_OK;
}

static int SET_source_mac(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->nic.my_mac_count) {
            fprintf(masscan->echo, "source mac = %s\n",
                macaddress_fmt(masscan->nic.source_mac).string);
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
    if (macaddress_is_equal(masscan->nic.source_mac, source_mac)) {
        /* suppresses warning message about duplicate MAC addresses if
            * they are in fact the same */
        return CONF_OK;
    }

    /* Warn if we are overwriting a Mac address */
    if (masscan->nic.my_mac_count != 0) {
        ipaddress_formatted_t fmt1 = macaddress_fmt(masscan->nic.source_mac);
        ipaddress_formatted_t fmt2 = macaddress_fmt(source_mac);
        fprintf(stderr, "[-] WARNING: overwriting MAC address, was %s, now %s\n",
            fmt1.string,
            fmt2.string);
    }

    masscan->nic.source_mac = source_mac;
    masscan->nic.my_mac_count = 1;

    return CONF_OK;
}

static int SET_router_ip(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->nic.router_ip) {
            ipaddress_formatted_t router_ip =
                ipv4address_fmt(masscan->nic.router_ip);
            fprintf(masscan->echo, "router ip first = %s\n", router_ip.string);
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

    masscan->nic.router_ip = range.begin;

    return CONF_OK;
}

static int SET_router_mac(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->nic.router_mac_ipv4.addr[0]) {
            fprintf(masscan->echo, "IPv4 router mac = %s\n",
                macaddress_fmt(masscan->nic.router_mac_ipv4).string);
        }

        if (masscan->nic.router_mac_ipv6.addr[0]) {
            fprintf(masscan->echo, "IPv6 router mac = %s\n",
                macaddress_fmt(masscan->nic.router_mac_ipv6).string);
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
        masscan->nic.router_mac_ipv4 = router_mac;
    else if (EQUALS("router-mac-ipv6", name))
        masscan->nic.router_mac_ipv6 = router_mac;
    else {
        masscan->nic.router_mac_ipv4 = router_mac;
        masscan->nic.router_mac_ipv6 = router_mac;
    }

    return CONF_OK;
}

/**
 * read conf file and set params directly
*/
static int SET_read_conf(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
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

        masscan_set_parameter(masscan, name, value);
    }

    fclose(fp);

    if (EQUALS("resume", name))
        masscan->output.is_append = true;

    return CONF_OK;
}

static int SET_hello_file(struct Masscan *masscan, const char *name, const char *value)
{
    unsigned index;
    FILE *fp;
    char buf[16384];
    char buf2[16384];
    size_t bytes_read;
    size_t bytes_encoded;
    char foo[64];

    if (masscan->echo) {
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
    
    masscan_set_parameter(masscan, foo, buf2);

    return CONF_OK;
}

static int SET_hello_string(struct Masscan *masscan, const char *name, const char *value)
{
    unsigned index;
    char *value2;
    struct TcpCfgPayloads *pay;

    if (masscan->echo) {
        for (pay = masscan->payloads.tcp; pay; pay = pay->next) {
            fprintf(masscan->echo, "hello-string[%u] = %s\n",
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
    pay->next = masscan->payloads.tcp;
    masscan->payloads.tcp = pay;
    return CONF_OK;
}

static int SET_hello_timeout(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->tcp_hello_timeout || masscan->echo_all)
            fprintf(masscan->echo, "hello-timeout = %u\n", masscan->tcp_hello_timeout);
        return 0;
    }
    masscan->tcp_hello_timeout = (unsigned)parseInt(value);
    return CONF_OK;
}

static int SET_http_cookie(struct Masscan *masscan, const char *name, const char *value)
{
    unsigned char *newvalue;
    size_t value_length;

    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->http.cookies_count || masscan->echo_all) {
            size_t i;
            for (i=0; i<masscan->http.cookies_count; i++) {
                fprintf(masscan->echo,
                        "http-cookie = %.*s\n",
                        (unsigned)masscan->http.cookies[i].value_length,
                        masscan->http.cookies[i].value);
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
    if (masscan->http.cookies_count < sizeof(masscan->http.cookies)/sizeof(masscan->http.cookies[0])) {
        size_t x = masscan->http.cookies_count;
        masscan->http.cookies[x].value = newvalue;
        masscan->http.cookies[x].value_length = value_length;
        masscan->http.cookies_count++;
    }
    return CONF_OK;
}

static int SET_http_header(struct Masscan *masscan, const char *name, const char *value)
{
    unsigned name_length;
    char *newname;
    unsigned char *newvalue;
    size_t value_length;

    if (masscan->echo) {
        if (masscan->http.headers_count || masscan->echo_all) {
            size_t i;
            for (i=0; i<masscan->http.headers_count; i++) {
                if (masscan->http.headers[i].name == 0)
                    continue;
                fprintf(masscan->echo,
                        "http-header = %s:%.*s\n",
                        masscan->http.headers[i].name,
                        (unsigned)masscan->http.headers[i].value_length,
                        masscan->http.headers[i].value);
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
    if (masscan->http.headers_count < sizeof(masscan->http.headers)/sizeof(masscan->http.headers[0])) {
        size_t x = masscan->http.headers_count;
        masscan->http.headers[x].name = newname;
        masscan->http.headers[x].value = newvalue;
        masscan->http.headers[x].value_length = value_length;
        masscan->http.headers_count++;
    }
    return CONF_OK;
}

static int SET_http_method(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->http.method || masscan->echo_all)
            fprintf(masscan->echo, "http-method = %.*s\n", (unsigned)masscan->http.method_length, masscan->http.method);
        return 0;
    }
    if (masscan->http.method)
        free(masscan->http.method);
    masscan->http.method_length = strlen(value);
    masscan->http.method = MALLOC(masscan->http.method_length+1);
    memcpy(masscan->http.method, value, masscan->http.method_length+1);
    return CONF_OK;
}
static int SET_http_url(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->http.url || masscan->echo_all)
            fprintf(masscan->echo, "http-url = %.*s\n", (unsigned)masscan->http.url_length, masscan->http.url);
        return 0;
    }
    if (masscan->http.url)
        free(masscan->http.url);
    masscan->http.url_length = strlen(value);
    masscan->http.url = MALLOC(masscan->http.url_length+1);
    memcpy(masscan->http.url, value, masscan->http.url_length+1);
    return CONF_OK;
}
static int SET_http_version(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->http.version || masscan->echo_all)
            fprintf(masscan->echo, "http-version = %.*s\n", (unsigned)masscan->http.version_length, masscan->http.version);
        return 0;
    }
    if (masscan->http.version)
        free(masscan->http.version);
    masscan->http.version_length = strlen(value);
    masscan->http.version = MALLOC(masscan->http.version_length+1);
    memcpy(masscan->http.version, value, masscan->http.version_length+1);
    return CONF_OK;
}
static int SET_http_host(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->http.host || masscan->echo_all)
            fprintf(masscan->echo, "http-host = %.*s\n", (unsigned)masscan->http.host_length, masscan->http.host);
        return 0;
    }
    if (masscan->http.host)
        free(masscan->http.host);
    masscan->http.host_length = strlen(value);
    masscan->http.host = MALLOC(masscan->http.host_length+1);
    memcpy(masscan->http.host, value, masscan->http.host_length+1);
    return CONF_OK;
}

static int SET_http_user_agent(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->http.user_agent || masscan->echo_all)
            fprintf(masscan->echo, "http-user-agent = %.*s\n", (unsigned)masscan->http.user_agent_length, masscan->http.user_agent);
        return 0;
    }
    if (masscan->http.user_agent)
        free(masscan->http.user_agent);
    masscan->http.user_agent_length = strlen(value);
    masscan->http.user_agent = MALLOC(masscan->http.user_agent_length+1);
    memcpy( masscan->http.user_agent,
            value,
            masscan->http.user_agent_length+1
            );
    return CONF_OK;
}

static int SET_http_payload(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->http.payload || masscan->echo_all)
            fprintf(masscan->echo, "http-payload = %.*s\n", (unsigned)masscan->http.payload_length, masscan->http.payload);
        return 0;
    }
    masscan->http.payload_length = strlen(value);
    masscan->http.payload = REALLOC(masscan->http.payload, masscan->http.payload_length+1);
    memcpy( masscan->http.payload,
            value,
            masscan->http.payload_length+1
            );
    return CONF_OK;
}

static int SET_packet_trace(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (masscan->echo) {
        if (masscan->nmap.packet_trace || masscan->echo_all)
            fprintf(masscan->echo, "packet-trace = %s\n",
                masscan->nmap.packet_trace?"true":"false");
        return 0;
    }
    masscan->nmap.packet_trace = parseBoolean(value);
    return CONF_OK;
}

static int SET_json_status(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (masscan->echo) {
        if (masscan->output.is_status_ndjson || masscan->echo_all)
            fprintf(masscan->echo, "ndjson-status = %s\n", masscan->output.is_status_ndjson?"true":"false");
        return 0;
    }
    masscan->output.is_status_ndjson = parseBoolean(value);
    return CONF_OK;
}

static int SET_min_packet(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->min_packet_size != 60 || masscan->echo_all)
            fprintf(masscan->echo, "min-packet = %u\n", masscan->min_packet_size);
        return 0;
    }
    masscan->min_packet_size = (unsigned)parseInt(value);
    return CONF_OK;
}


static int SET_nobanners(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        return 0;
    }
    masscan->is_banners = !parseBoolean(value);
    return CONF_OK;
}

static int SET_noreset(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->is_noreset1 || masscan->echo_all)
            fprintf(masscan->echo, "noreset1 = %s\n", masscan->is_noreset1?"true":"false");
        if (masscan->is_noreset2 || masscan->echo_all)
            fprintf(masscan->echo, "noreset2 = %s\n", masscan->is_noreset2?"true":"false");
        return 0;
    }

    if (EQUALS(name, "noreset1"))
        masscan->is_noreset1 = parseBoolean(value);
    else if (EQUALS(name, "noreset2"))
        masscan->is_noreset2 = parseBoolean(value);
    else if (EQUALS(name, "noreset")) {
        masscan->is_noreset1 = parseBoolean(value);
        masscan->is_noreset2 = parseBoolean(value);
    }

    return CONF_OK;
}

static int SET_nmap_data_length(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    
    if (masscan->echo) {
        if (masscan->nmap.data_length || masscan->echo_all)
            fprintf(masscan->echo, "nmap-data-length = %u\n", masscan->nmap.data_length);
        return 0;
    }
    
    unsigned x = parseInt(value);
    if (x >= 1514 - 14 - 40) {
        fprintf(stderr, "error: %s=<n>: expected number less than 1500\n", name);
        return CONF_ERR;
    } else {
        masscan->nmap.data_length = x;
    }

    return CONF_OK;
}

static int SET_nmap_datadir(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    
    if (masscan->echo) {
        if (masscan->nmap.datadir[0] || masscan->echo_all)
            fprintf(masscan->echo, "nmap-datadir = %s\n", masscan->nmap.datadir);
        return 0;
    }
    
    safe_strcpy(masscan->nmap.datadir, sizeof(masscan->nmap.datadir), value);

    return CONF_OK;
}

static int SET_nmap_payloads(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    
    if (masscan->echo) {
        if ((masscan->payloads.nmap_payloads_filename && masscan->payloads.nmap_payloads_filename[0]) || masscan->echo_all)
            fprintf(masscan->echo, "nmap-payloads = %s\n", masscan->payloads.nmap_payloads_filename);
        return 0;
    }
    
    if (masscan->payloads.nmap_payloads_filename)
        free(masscan->payloads.nmap_payloads_filename);
    masscan->payloads.nmap_payloads_filename = strdup(value);

    return CONF_OK;
}

static int SET_nmap_service_probes(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    
    if (masscan->echo) {
        if ((masscan->payloads.nmap_service_probes_filename && masscan->payloads.nmap_service_probes_filename[0]) || masscan->echo_all)
            fprintf(masscan->echo, "nmap-service-probes = %s\n", masscan->payloads.nmap_service_probes_filename);
        return 0;
    }
    
    if (masscan->payloads.nmap_service_probes_filename)
        free(masscan->payloads.nmap_service_probes_filename);
    masscan->payloads.nmap_service_probes_filename = strdup(value);
    
    
    return CONF_OK;
}

static int SET_offline(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (masscan->echo) {
        if (masscan->is_offline || masscan->echo_all)
            fprintf(masscan->echo, "offline = %s\n", masscan->is_offline?"true":"false");
        return 0;
    }
    masscan->is_offline = parseBoolean(value);
    return CONF_OK;
}

static int SET_output_append(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->output.is_append || masscan->echo_all)
            fprintf(masscan->echo, "output-append = %s\n",
                    masscan->output.is_append?"true":"false");
        return 0;
    }
    if (EQUALS("overwrite", name) || !parseBoolean(value))
        masscan->output.is_append = 0;
    else
        masscan->output.is_append = 1;
    return CONF_OK;
}

static int SET_output_filename(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->output.filename[0] || masscan->echo_all)
            fprintf(masscan->echo, "output-filename = %s\n", masscan->output.filename);
        return 0;
    }
    if (masscan->output.format == 0)
        masscan->output.format = Output_XML; /*TODO: Why is the default XML?*/
    safe_strcpy(masscan->output.filename,
             sizeof(masscan->output.filename),
             value);
    return CONF_OK;
}

static int SET_output_format(struct Masscan *masscan, const char *name, const char *value)
{
    enum OutputFormat x = 0;
    UNUSEDPARM(name);
    if (masscan->echo) {
        FILE *fp = masscan->echo;
        ipaddress_formatted_t fmt;
        switch (masscan->output.format) {
            case Output_Default:    if (masscan->echo_all) fprintf(fp, "output-format = interactive\n"); break;
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
                fmt = ipaddress_fmt(masscan->redis.ip);
                fprintf(fp, "output-format = redis\n");
                fprintf(fp, "redis = %s %u\n", fmt.string, masscan->redis.port);
                break;
                
            default:
                fprintf(fp, "output-format = unknown(%u)\n", masscan->output.format);
                break;
        }
        return 0;
    }
    if (EQUALS("unknown(0)", value))        x = Output_Interactive;
    else if (EQUALS("interactive", value))  x = Output_Interactive;
    else if (EQUALS("list", value))         x = Output_List;
    else if (EQUALS("unicornscan", value))  x = Output_Unicornscan;
    else if (EQUALS("xml", value))          x = Output_XML;
    else if (EQUALS("binary", value))       x = Output_Binary;
    else if (EQUALS("greppable", value))    x = Output_Grepable;
    else if (EQUALS("grepable", value))     x = Output_Grepable;
    else if (EQUALS("json", value))         x = Output_JSON;
    else if (EQUALS("ndjson", value))       x = Output_NDJSON;
    else if (EQUALS("certs", value))        x = Output_Certs;
    else if (EQUALS("none", value))         x = Output_None;
    else if (EQUALS("redis", value))        x = Output_Redis;
    else if (EQUALS("hostonly", value))     x = Output_Hostonly;
    else {
        fprintf(stderr, "FAIL: unknown output-format: %s\n", value);
        fprintf(stderr, "  hint: 'binary', 'xml', 'grepable', ...\n");
        return CONF_ERR;
    }
    masscan->output.format = x;

    return CONF_OK;
}

static int SET_output_noshow(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->echo_all) {
            fprintf(masscan->echo, "output-noshow = %s%s%s\n",
                    (!masscan->output.is_show_open)?"open,":"",
                    (!masscan->output.is_show_closed)?"closed,":"",
                    (!masscan->output.is_show_host)?"host,":""
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
            masscan->output.is_show_open = 0;
        else if (EQUALSx("closed", val2, val2_len) || EQUALSx("close", val2, val2_len))
            masscan->output.is_show_closed = 0;
        else if (EQUALSx("open", val2, val2_len))
            masscan->output.is_show_host = 0;
        else if (EQUALSx("all",val2,val2_len)) {
            masscan->output.is_show_open = 0;
            masscan->output.is_show_host = 0;
            masscan->output.is_show_closed = 0;
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

static int SET_output_show(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->echo_all) {
            fprintf(masscan->echo, "output-show = %s%s%s\n",
                    masscan->output.is_show_open?"open,":"",
                    masscan->output.is_show_closed?"closed,":"",
                    masscan->output.is_show_host?"host,":""
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
            masscan->output.is_show_open = 1;
        else if (EQUALSx("closed", val2, val2_len) || EQUALSx("close", val2, val2_len))
            masscan->output.is_show_closed = 1;
        else if (EQUALSx("open", val2, val2_len))
            masscan->output.is_show_host = 1;
        else if (EQUALSx("all",val2,val2_len)) {
            masscan->output.is_show_open = 1;
            masscan->output.is_show_host = 1;
            masscan->output.is_show_closed = 1;
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

static int SET_output_redis(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->output.format==Output_Redis || masscan->echo_all) {
            fprintf(masscan->echo, "output-redis = %s\n",
                masscan->output.format==Output_Redis?"true":"false");
            if (masscan->output.format==Output_Redis) {
            fprintf(masscan->echo, "redis address = %s:%u\n",
                ipv4address_fmt((ipv4address)(masscan->redis.ip.ipv4)).string,
                masscan->redis.port);
            }
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
    masscan->redis.ip.ipv4 = range.begin;
    masscan->redis.ip.version = 4;

    masscan->redis.port = port;
    masscan->output.format = Output_Redis;
    safe_strcpy(masscan->output.filename, 
                sizeof(masscan->output.filename), 
                "<redis>");

    return CONF_OK;
}

static int SET_redis_password(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->redis.password[0] || masscan->echo_all)
            fprintf(masscan->echo, "redis-password = %s\n",
                masscan->redis.password);
        return 0;
    }
    safe_strcpy(masscan->redis.password, 20, value);
    return CONF_OK;
}

static int SET_reason(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->output.is_reason || masscan->echo_all)
            fprintf(masscan->echo, "show reason = %s\n",
                masscan->output.is_reason?"true":"false");
        return 0;
    }
    masscan->output.is_reason =  parseBoolean(value);
    return CONF_OK;
}

static int SET_output_show_open(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (masscan->echo) {
        return 0;
    }
    /* "open" "open-only" */
    masscan->output.is_show_open = 1;
    masscan->output.is_show_closed = 0;
    masscan->output.is_show_host = 0;
    return CONF_OK;
}

/* Specifies a 'libpcap' file where the received packets will be written.
 * This is useful while debugging so that we can see what exactly is
 * going on. It's also an alternate mode for getting output from this
 * program. Instead of relying upon this program's determination of what
 * ports are open or closed, you can instead simply parse this capture
 * file yourself and make your own determination */
static int SET_pcap_filename(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->pcap_filename[0])
            fprintf(masscan->echo, "pcap-filename = %s\n", masscan->pcap_filename);
        return 0;
    }
    if (value)
        safe_strcpy(masscan->pcap_filename, sizeof(masscan->pcap_filename), value);
    return CONF_OK;
}

/* Specifies a 'libpcap' file from which to read packet-payloads. The payloads found
 * in this file will serve as the template for spewing out custom packets. There are
 * other options that can set payloads as well, like "--nmap-payloads" for reading
 * their custom payload file, as well as the various "hello" options for specifying
 * the string sent to the server once a TCP connection has been established. */
static int SET_pcap_payloads(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if ((masscan->payloads.pcap_payloads_filename && masscan->payloads.pcap_payloads_filename[0]) || masscan->echo_all)
            fprintf(masscan->echo, "pcap-payloads = %s\n", masscan->payloads.pcap_payloads_filename);
        return 0;
    }
    
    if (masscan->payloads.pcap_payloads_filename)
        free(masscan->payloads.pcap_payloads_filename);
    masscan->payloads.pcap_payloads_filename = strdup(value);
    
    /* file will be loaded in "masscan_load_database_files()" */
    
    return CONF_OK;
}

static int SET_status(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (!masscan->output.is_status_updates || masscan->echo_all)
            fprintf(masscan->echo, "update status = %s\n",
                masscan->output.is_status_updates?"true":"false");
        return 0;
    }
    
    if (EQUALS("status", name))
        masscan->output.is_status_updates = parseBoolean(value);
    else if (EQUALS("nostatus", name))
        masscan->output.is_status_updates = !parseBoolean(value);
    
    return CONF_OK;
}

static int SET_interactive(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->output.is_interactive || masscan->echo_all)
            fprintf(masscan->echo, "output interacitve = %s\n",
                masscan->output.is_interactive?"true":"false");
        return 0;
    }
    
    if (EQUALS("interactive", name))
        masscan->output.is_interactive = parseBoolean(value);
    else if (EQUALS("nointeractive", name))
        masscan->output.is_interactive = !parseBoolean(value);
    
    return CONF_OK;
}

static int SET_echo(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->echo_all)
            fprintf(masscan->echo, "echo = %s\n", masscan->echo?"true":"false");
        return 0;
    }
    
    if (EQUALS("echo", name) && parseBoolean(value))
        masscan->op = Operation_Echo;
    else if (EQUALS("echo-all", name) && parseBoolean(value))
        masscan->op = Operation_EchoAll;
    else if (EQUALS("echo-cidr", name) && parseBoolean(value))
        masscan->op = Operation_EchoCidr;
    
    return CONF_OK;
}


static int SET_rate(struct Masscan *masscan, const char *name, const char *value)
{
    double rate = 0.0;
    double point = 10.0;
    unsigned i;
    
    if (masscan->echo) {
        if ((unsigned)(masscan->max_rate * 100000) % 100000) {
            /* print as floating point number, which is rare */
            fprintf(masscan->echo, "rate = %f\n", masscan->max_rate);
        } else {
            /* pretty print as just an integer, which is what most people
             * expect */
            fprintf(masscan->echo, "rate = %-10.0f\n", masscan->max_rate);
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
    
    masscan->max_rate = rate;
    return CONF_OK;
}

static int SET_resume_count(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->resume.count || masscan->echo_all) {
            fprintf(masscan->echo, "resume-count = %" PRIu64 "\n", masscan->resume.count);
        }
        return 0;
    }
    masscan->resume.count = parseInt(value);
    return CONF_OK;
}

static int SET_resume_index(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->resume.index  || masscan->echo_all) {
            fprintf(masscan->echo, "\n# resume information\n");
            fprintf(masscan->echo, "resume-index = %" PRIu64 "\n", masscan->resume.index);
        }
        return 0;
    }
    masscan->resume.index = parseInt(value);
    return CONF_OK;
}

static int SET_retries(struct Masscan *masscan, const char *name, const char *value)
{
    uint64_t x;
    
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->retries || masscan->echo_all)
            fprintf(masscan->echo, "retries = %u\n", masscan->retries);
        return 0;
    }
    x = strtoul(value, 0, 0);
    if (x >= 1000) {
        fprintf(stderr, "FAIL: retries=<n>: expected number less than 1000\n");
        return CONF_ERR;
    }
    masscan->retries = (unsigned)x;
    return CONF_OK;
    
}

static int SET_rotate_time(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->output.rotate.timeout || masscan->echo_all)
            fprintf(masscan->echo, "rotate = %u\n", masscan->output.rotate.timeout);
        return 0;
    }
    masscan->output.rotate.timeout = (unsigned)parseTime(value);
    return CONF_OK;
}
static int SET_rotate_directory(struct Masscan *masscan, const char *name, const char *value)
{
    char *p;
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (memcmp(masscan->output.rotate.directory, ".",2) != 0 || masscan->echo_all) {
            fprintf(masscan->echo, "rotate-dir = %s\n", masscan->output.rotate.directory);
        }
        return 0;
    }
    safe_strcpy(   masscan->output.rotate.directory,
             sizeof(masscan->output.rotate.directory),
             value);
    /* strip trailing slashes */
    p = masscan->output.rotate.directory;
    while (*p && (p[strlen(p)-1] == '/' || p[strlen(p)-1] == '\\')) /* Fix for #561 */
        p[strlen(p)-1] = '\0';
    return CONF_OK;
}
static int SET_rotate_offset(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    /* Time offset, otherwise output files are aligned to nearest time
     * interval, e.g. at the start of the hour for "hourly" */
    if (masscan->echo) {
        if (masscan->output.rotate.offset || masscan->echo_all)
            fprintf(masscan->echo, "rotate-offset = %u\n", masscan->output.rotate.offset);
        return 0;
    }
    masscan->output.rotate.offset = (unsigned)parseTime(value);
    return CONF_OK;
}
static int SET_rotate_filesize(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->output.rotate.filesize || masscan->echo_all)
            fprintf(masscan->echo, "rotate-size = %" PRIu64 "\n", masscan->output.rotate.filesize);
        return 0;
    }
    masscan->output.rotate.filesize = parseSize(value);
    return CONF_OK;
    
}

static int SET_bpf_filter(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->bpf_filter || masscan->echo_all)
            fprintf(masscan->echo, "bpf-filter = %s\n", masscan->bpf_filter);
        return 0;
    }

    size_t len = strlen(value) + 1;
    if (masscan->bpf_filter)
        free(masscan->bpf_filter);
    masscan->bpf_filter = MALLOC(len);
    memcpy(masscan->bpf_filter, value, len);
    
    return CONF_OK;
}

static int SET_script(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if ((masscan->scripting.name && masscan->scripting.name[0]) || masscan->echo_all)
            fprintf(masscan->echo, "script = %s\n", masscan->scripting.name);
        return 0;
    }
    if (value && value[0])
        masscan->is_scripting = 1;
    else
        masscan->is_scripting = 0;
    
    if (masscan->scripting.name)
        free(masscan->scripting.name);
    
    masscan->scripting.name = strdup(value);
    
    return CONF_OK;
}


static int SET_seed(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        fprintf(masscan->echo, "seed = %" PRIu64 "\n", masscan->seed);
        return 0;
    }
    if (EQUALS("time", value))
        masscan->seed = time(0);
    else
        masscan->seed = parseInt(value);
    return CONF_OK;
}

static int SET_banner1(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (masscan->echo) {
        return 0;
    }
    banner1_test(value);
    return CONF_ERR;
}

static int SET_delimiter(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (masscan->echo) {
        fprintf(masscan->echo, "-=-=-=-=-=-\n");
        return 0;
    }
    return CONF_OK;
}

static int SET_vuln_check(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->is_heartbleed || masscan->echo_all)
            fprintf(masscan->echo, "vulncheck heartbleed = %s\n",
                masscan->is_heartbleed?"true":"false");
        if (masscan->is_ticketbleed || masscan->echo_all)
            fprintf(masscan->echo, "vulncheck ticketbleed = %s\n",
                masscan->is_ticketbleed?"true":"false");
        if (masscan->is_poodle_sslv3 || masscan->echo_all)
            fprintf(masscan->echo, "vulncheck poodle-sslv3 = %s\n",
                masscan->is_poodle_sslv3?"true":"false");
        return 0;
    }

    if (EQUALS("heartbleed", value)) {
        masscan->is_heartbleed = 1;
        masscan_set_parameter(masscan, "no-capture", "cert");
        masscan_set_parameter(masscan, "no-capture", "heartbleed");
        masscan_set_parameter(masscan, "banners", "true");
    } else if (EQUALS("ticketbleed", value)) {
        masscan->is_ticketbleed = 1;
        masscan_set_parameter(masscan, "no-capture", "cert");
        masscan_set_parameter(masscan, "no-capture", "ticketbleed");
        masscan_set_parameter(masscan, "banners", "true");
    } else if (EQUALS("poodle", value) || EQUALS("sslv3", value)) {
        masscan->is_poodle_sslv3 = 1;
        masscan_set_parameter(masscan, "no-capture", "cert");
        masscan_set_parameter(masscan, "banners", "true");
    } else {
        if (!vulncheck_lookup(value)) {
            fprintf(stderr, "FAIL: vuln check '%s' does not exist\n", value);
            fprintf(stderr, "  hint: use '--vuln list' to list available scripts\n");
            return CONF_ERR;
        }
        if (masscan->vuln_name != NULL) {
            if (strcmp(masscan->vuln_name, value) != 0) {
                fprintf(stderr, "FAIL: only one vuln check supported at a time\n");
                fprintf(stderr, "  hint: '%s' is existing vuln check, '%s' is new vuln check\n",
                        masscan->vuln_name, value);
                return CONF_ERR;
            }
        }
        masscan->vuln_name = vulncheck_lookup(value)->name;
    }

    return CONF_OK;
}

static int SET_version(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (masscan->echo) {
        return 0;
    }

    const char *cpu = "unknown";
    const char *compiler = "unknown";
    const char *compiler_version = "unknown";
    const char *os = "unknown";
    printf("\n");
    printf("Xtate version %s\n( %s )\n", 
        XTATE_VERSION,
        "https://github.com/lfishRhungry/xtate"
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

static int SET_usage(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (masscan->echo) {
        return 0;
    }

    printf("\n");
    printf("Welcome to Xtate!\n");
    printf("\n");
    printf("usage: xtate [options] [<IP|RANGE>... -p PORT[,PORT...]]\n");
    printf("\n");
    printf("original examples in masscan:\n");
    printf("    xtate -p 80,8000-8100 10.0.0.0/8 --rate=10000\n");
    printf("        scan some web ports on 10.x.x.x at 10kpps\n");
    printf("\n");
    printf("    xtate -p 80 10.0.0.0/8 --banners -oB <filename>\n");
    printf("        save results of scan in binary format to <filename>\n");
    printf("\n");
    printf("    xtate --open --banners --readscan <filename> -oX <savefile>\n");
    printf("        read binary scan results in <filename> and save them as xml in <savefile>\n");
    printf("\n");
    printf("    xtate 10.0.0.0/8 -p 21,110 --stateless\n");
    printf("        scan some ftp & pop3 ports with default NULL probe\n");
    printf("\n");
    printf("    xtate 10.0.0.0/8 -p 80 --stateless --probe getrequest\n");
    printf("        scan some web ports with GetRequest probe\n");
    printf("\n");
    printf("    xtate 10.0.0.0/8 -p 110 --stateless --capture stateless\n");
    printf("        capture banner result\n");
    printf("\n");
    printf("    xtate 10.0.0.0/8 -p 110 --stateless --pcap <pcapfile> -oX <xmlfile>\n");
    printf("        save packet result in <pcapfile> and save scan result in <xmlfile>\n");
    printf("\n");

    return CONF_ERR;
}

static int SET_help(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (masscan->echo) {
        return 0;
    }

    printf("\nWelcome to Xtate!\n\n");

    return CONF_ERR;
}

static int SET_log_level(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(value);
    if (masscan->echo) {
        if (masscan->shard.of > 1  || masscan->echo_all)
            fprintf(masscan->echo, "shard = %u/%u\n", masscan->shard.one, masscan->shard.of);
        return 0;
    }

    LOG_add_level(strlen(name));
    
    return CONF_OK;
}

static int SET_shard(struct Masscan *masscan, const char *name, const char *value)
{
    unsigned one = 0;
    unsigned of = 0;

    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->shard.of > 1  || masscan->echo_all)
            fprintf(masscan->echo, "shard = %u/%u\n", masscan->shard.one, masscan->shard.of);
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
    masscan->shard.one = one;
    masscan->shard.of = of;
    return CONF_OK;
}

static int SET_output_stylesheet(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->output.stylesheet[0] || masscan->echo_all)
            fprintf(masscan->echo, "stylesheet = %s\n", masscan->output.stylesheet);
        return 0;
    }


    if (name[0]=='n') {
        masscan->output.stylesheet[0] = '\0';
        return CONF_OK;
    }
    
    if (masscan->output.format == 0)
        masscan->output.format = Output_XML;

    const char webxml[] =  "http://nmap.org/svn/docs/nmap.xsl";
    if (EQUALS(name, "webxml"))
        safe_strcpy(masscan->output.stylesheet, sizeof(masscan->output.stylesheet), webxml);
    else
        safe_strcpy(masscan->output.stylesheet, sizeof(masscan->output.stylesheet), value);
    return CONF_OK;
}

static int SET_top_port(struct Masscan *masscan, const char *name, const char *value)
{
    unsigned default_value = 20;

    if (masscan->echo) {
        /* don't echo: this instead triggers filling the `--port`
         * list, so the ports themselves will be echoed, not this
         * parameter */
        return 0;
    }

    if (value == 0 || value[0] == '\0') {
        /* can be specified by itself on the command-line, alone
         * without a following parameter */
        /* ex: `--top-ports` */
        masscan->top_ports = default_value;
    } else if (isBoolean(value)) {
        /* ex: `--top-ports enable` */
        if (parseBoolean(value))
            masscan->top_ports = default_value;
        else
            masscan->top_ports = 0;
    } else if (isInteger(value)) {
        /* ex: `--top-ports 5` */
        uint64_t num = parseInt(value);
        masscan->top_ports = (unsigned)num;
    } else {
        fprintf(stderr, "[-] %s: bad value: %s\n", name, value);
        return CONF_ERR;
    }
    return CONF_OK;
}

static int SET_tcp_mss(struct Masscan *masscan, const char *name, const char *value)
{
    /* h/t @IvreRocks */
    static const unsigned default_mss = 1460;

    if (masscan->echo) {
        if (masscan->templ_opts) {
            switch (masscan->templ_opts->tcp.is_mss) {
                case Default:
                    break;
                case Add:
                    if (masscan->templ_opts->tcp.mss == default_mss)
                        fprintf(masscan->echo, "tcp-mss = %s\n", "enable");
                    else
                        fprintf(masscan->echo, "tcp-mss = %u\n",
                                masscan->templ_opts->tcp.mss);
                    break;
                case Remove:
                    fprintf(masscan->echo, "tcp-mss = %s\n", "disable");
                    break;
                default:
                    break;
            }
        }
        return 0;
    }

    if (masscan->templ_opts == NULL)
        masscan->templ_opts = calloc(1, sizeof(*masscan->templ_opts));

    if (value == 0 || value[0] == '\0') {
        /* no following parameter, so interpret this to mean "enable" */
        masscan->templ_opts->tcp.is_mss = Add;
        masscan->templ_opts->tcp.mss = default_mss; /* 1460 */
    } else if (isBoolean(value)) {
        /* looking for "enable" or "disable", but any boolean works,
         * like "true/false" or "off/on" */
        if (parseBoolean(value)) {
            masscan->templ_opts->tcp.is_mss = Add;
            masscan->templ_opts->tcp.mss = default_mss; /* 1460 */
        } else
            masscan->templ_opts->tcp.is_mss = Remove;
    } else if (isInteger(value)) {
        /* A specific number was specified */
        uint64_t num = parseInt(value);
        if (num >= 0x10000)
            goto fail;
        masscan->templ_opts->tcp.is_mss = Add;
        masscan->templ_opts->tcp.mss = (unsigned)num;
    } else
        goto fail;

    return CONF_OK;
fail:
    fprintf(stderr, "[-] %s: bad value: %s\n", name, value);
    return CONF_ERR;
}

static int SET_tcp_wscale(struct Masscan *masscan, const char *name, const char *value)
{
    static const unsigned default_value = 3;

    if (masscan->echo) {
        if (masscan->templ_opts) {
            switch (masscan->templ_opts->tcp.is_wscale) {
                case Default:
                    break;
                case Add:
                    if (masscan->templ_opts->tcp.wscale == default_value)
                        fprintf(masscan->echo, "tcp-wscale = %s\n", "enable");
                    else
                        fprintf(masscan->echo, "tcp-wscale = %u\n",
                                masscan->templ_opts->tcp.wscale);
                    break;
                case Remove:
                    fprintf(masscan->echo, "tcp-wscale = %s\n", "disable");
                    break;
                default:
                    break;
            }
        }
        return 0;
    }

    if (masscan->templ_opts == NULL)
        masscan->templ_opts = calloc(1, sizeof(*masscan->templ_opts));

    if (value == 0 || value[0] == '\0') {
        masscan->templ_opts->tcp.is_wscale = Add;
        masscan->templ_opts->tcp.wscale = default_value;
    } else if (isBoolean(value)) {
        if (parseBoolean(value)) {
            masscan->templ_opts->tcp.is_wscale = Add;
            masscan->templ_opts->tcp.wscale = default_value;
        } else
            masscan->templ_opts->tcp.is_wscale = Remove;
    } else if (isInteger(value)) {
        uint64_t num = parseInt(value);
        if (num >= 255)
            goto fail;
        masscan->templ_opts->tcp.is_wscale = Add;
        masscan->templ_opts->tcp.wscale = (unsigned)num;
    } else
        goto fail;

    return CONF_OK;
fail:
    fprintf(stderr, "[-] %s: bad value: %s\n", name, value);
    return CONF_ERR;
}

static int SET_tcp_tsecho(struct Masscan *masscan, const char *name, const char *value)
{
    static const unsigned default_value = 0x12345678;

    if (masscan->echo) {
        if (masscan->templ_opts) {
            switch (masscan->templ_opts->tcp.is_tsecho) {
                case Default:
                    break;
                case Add:
                    if (masscan->templ_opts->tcp.tsecho == default_value)
                        fprintf(masscan->echo, "tcp-tsecho = %s\n", "enable");
                    else
                        fprintf(masscan->echo, "tcp-tsecho = %u\n",
                                masscan->templ_opts->tcp.tsecho);
                    break;
                case Remove:
                    fprintf(masscan->echo, "tcp-tsecho = %s\n", "disable");
                    break;
                default:
                    break;
            }
        }
        return 0;
    }

    if (masscan->templ_opts == NULL)
        masscan->templ_opts = calloc(1, sizeof(*masscan->templ_opts));

    if (value == 0 || value[0] == '\0') {
        masscan->templ_opts->tcp.is_tsecho = Add;
        masscan->templ_opts->tcp.tsecho = default_value;
    } else if (isBoolean(value)) {
        if (parseBoolean(value)) {
            masscan->templ_opts->tcp.is_tsecho = Add;
            masscan->templ_opts->tcp.tsecho = default_value;
        } else
            masscan->templ_opts->tcp.is_tsecho = Remove;
    } else if (isInteger(value)) {
        uint64_t num = parseInt(value);
        if (num >= 255)
            goto fail;
        masscan->templ_opts->tcp.is_tsecho = Add;
        masscan->templ_opts->tcp.tsecho = (unsigned)num;
    } else
        goto fail;

    return CONF_OK;
fail:
    fprintf(stderr, "[-] %s: bad value: %s\n", name, value);
    return CONF_ERR;
}

static int SET_tcp_sackok(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->templ_opts) {
            switch (masscan->templ_opts->tcp.is_sackok) {
                case Default:
                    break;
                case Add:
                    fprintf(masscan->echo, "tcp-sackok = %s\n", "enable");
                    break;
                case Remove:
                    fprintf(masscan->echo, "tcp-sackok = %s\n", "disable");
                    break;
                default:
                    break;
            }
        }
        return 0;
    }

    if (masscan->templ_opts == NULL)
        masscan->templ_opts = calloc(1, sizeof(*masscan->templ_opts));

    if (value == 0 || value[0] == '\0') {
        masscan->templ_opts->tcp.is_sackok = Add;
    } else if (isBoolean(value)) {
        if (parseBoolean(value)) {
            masscan->templ_opts->tcp.is_sackok = Add;
        } else
            masscan->templ_opts->tcp.is_sackok = Remove;
    } else if (isInteger(value)) {
        if (parseInt(value) != 0)
            masscan->templ_opts->tcp.is_sackok = Add;
    } else
        goto fail;

    return CONF_OK;
fail:
    fprintf(stderr, "[-] %s: bad value: %s\n", name, value);
    return CONF_ERR;
}

static int SET_blackrock_rounds(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (masscan->echo) {
        if (masscan->blackrock_rounds!=14 || masscan->echo_all)
            fprintf(masscan->echo, "blackrock rounds = %u\n", masscan->blackrock_rounds);
        return 0;
    }

    masscan->blackrock_rounds = (unsigned)parseInt(value);
    return CONF_OK;
}

static int SET_send_queue(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);

    if (masscan->echo) {
        if (masscan->is_sendq || masscan->echo_all)
            fprintf(masscan->echo, "send queue = %s\n", masscan->is_sendq?"true":"false");
        return 0;
    }

    masscan->is_sendq = parseBoolean(value);
    return CONF_OK;
}

static int SET_debug_tcp(struct Masscan *masscan, const char *name, const char *value)
{
    extern int is_tcp_debug; /* global */

    UNUSEDPARM(name);
    UNUSEDPARM(masscan);

    if (masscan->echo) {
        if (is_tcp_debug || masscan->echo_all)
            fprintf(masscan->echo, "tcp debug = %s\n", is_tcp_debug?"true":"false");
        return 0;
    }

    if (value == 0 || value[0] == '\0')
        is_tcp_debug = 1;
    else
        is_tcp_debug = parseBoolean(value);
    return CONF_OK;
}



struct ConfigParameter {
    const char *name;
    SET_PARAMETER set;
    unsigned flags;
    const char *alts[6];
};
enum {F_NONE, F_BOOL=1, F_NUMABLE=2};
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
    {"selftest",        SET_selftest,           F_BOOL, {"regress", "regression",0}},
    {"benchmark",       SET_benchmark,          F_BOOL, {0}},
    {"debug-if",        SET_debug_interface,    F_BOOL, {"debug-interface",0}},

    {"SCAN TYPE:",      SET_delimiter,          0,      {0}},

    {"arpscan",         SET_arpscan,            F_BOOL, {"arp",0}},
    {"ping",            SET_ping,            F_BOOL, {0}},
    {"oproto",          SET_oproto,             F_BOOL, {"oprotos",0}}, /*other IP protocol*/

    {"STATUS & OUTPUT & RESULT:",SET_delimiter, 0,      {0}},

    {"interactive",     SET_interactive,        F_BOOL, {"nointeractive",0}},
    {"status",          SET_status,             F_BOOL, {"nostatus",0}},
    {"json-status",     SET_json_status,        F_BOOL, {"status-json", 0}},

    {"output-filename", SET_output_filename,    0,      {"output-file",0}},
    {"output-format",   SET_output_format,      0,      {0}},
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
    {"nodedup",         SET_nodedup,            F_BOOL, {"nodedup1", "nodedup2", 0}},
    {"dedup-win",       SET_dedup_win,          F_NUMABLE, {"dedupwin", "dedupwin1", "dedupwin2", 0}},
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
masscan_set_parameter(struct Masscan *masscan,
                      const char *name, const char *value)
{
    /*
     * Go through configured list of parameters
     */
    {
        size_t i;
        
        for (i=0; config_parameters[i].name; i++) {
            if (EQUALS(config_parameters[i].name, name)) {
                if (CONF_ERR == config_parameters[i].set(masscan, name, value))
                    exit(0);
                return;
            } else {
                size_t j;
                for (j=0; config_parameters[i].alts[j]; j++) {
                    if (EQUALS(config_parameters[i].alts[j], name)) {
                        if (CONF_ERR == config_parameters[i].set(masscan, name, value))
                            exit(0);
                        return;
                    }
                }
            }
        }
    }

    fprintf(stderr, "CONF: unknown config option: %s=%s\n", name, value);
    exit(1);
}

static bool
is_numable(const char *name) {
    size_t i;

    for (i=0; config_parameters[i].name; i++) {
        if (EQUALS(config_parameters[i].name, name)) {
            return (config_parameters[i].flags & F_NUMABLE) == F_NUMABLE;
        } else {
            size_t j;
            for (j=0; config_parameters[i].alts[j]; j++) {
                if (EQUALS(config_parameters[i].alts[j], name)) {
                    return (config_parameters[i].flags & F_NUMABLE) == F_NUMABLE;
                }
            }
        }
    }
    return false;
}

/***************************************************************************
 * Command-line parsing code assumes every --parm is followed by a value.
 * This is a list of the parameters that don't follow the default.
 ***************************************************************************/
static int
is_singleton(const char *name)
{
    static const char *singletons[] = {
        "echo", "echo-all", "echo-cidr", "selftest", "self-test", "regress",
        "benchmark",
        "system-dns", "traceroute", "version",
        "version-light",
        "version-all", "version-trace",
        "osscan-limit", "osscan-guess",
        "badsum", "reason", "open", "open-only",
        "packet-trace", "release-memory",
        "log-errors", "append-output", "webxml",
        "no-stylesheet", "heartbleed", "ticketbleed",
        "send-eth", "send-ip", "iflist",
        "nmap", "trace-packet", "pfring", "sendq",
        "ping", "ping-sweep", "nobacktrace", "backtrace",
        "infinite", "nointeractive", "interactive", "status", "nostatus",
        "read-range", "read-ranges", "readrange", "read-ranges",
        0};
    size_t i;

    for (i=0; singletons[i]; i++) {
        if (EQUALS(singletons[i], name))
            return 1;
    }
    
    for (i=0; config_parameters[i].name; i++) {
        if (EQUALS(config_parameters[i].name, name)) {
            return (config_parameters[i].flags & F_BOOL) == F_BOOL;
        } else {
            size_t j;
            for (j=0; config_parameters[i].alts[j]; j++) {
                if (EQUALS(config_parameters[i].alts[j], name)) {
                    return (config_parameters[i].flags & F_BOOL) == F_BOOL;
                }
            }
        }
    }
    
    return 0;
}

/***************************************************************************
 ***************************************************************************/
void
masscan_load_database_files(struct Masscan *masscan)
{
    const char *filename;
    
    /*
     * "pcap-payloads"
     */
    filename = masscan->payloads.pcap_payloads_filename;
    if (filename) {
        if (masscan->payloads.udp == NULL)
            masscan->payloads.udp = payloads_udp_create();
        if (masscan->payloads.oproto == NULL)
            masscan->payloads.oproto = payloads_udp_create();

        payloads_read_pcap(filename, masscan->payloads.udp, masscan->payloads.oproto);
    }

    /*
     * `--nmap-payloads`
     */
    filename = masscan->payloads.nmap_payloads_filename;
    if (filename) {
        FILE *fp;
        
        fp = fopen(filename, "rt");
        if (fp == NULL) {
            fprintf(stderr, "[-] FAIL: --nmap-payloads\n");
            fprintf(stderr, "[-] %s:%s\n", filename, strerror(errno));
        } else {
            if (masscan->payloads.udp == NULL)
                masscan->payloads.udp = payloads_udp_create();
            
            payloads_udp_readfile(fp, filename, masscan->payloads.udp);
            
            fclose(fp);
        }
    }
    
    /*
     * "nmap-service-probes"
     */
    filename = masscan->payloads.nmap_service_probes_filename;
    if (filename) {
        if (masscan->payloads.probes)
            nmapserviceprobes_free(masscan->payloads.probes);
        
        masscan->payloads.probes = nmapserviceprobes_read_file(filename);
    }
}

/***************************************************************************
 * Read the configuration from the command-line.
 * Called by 'main()' when starting up.
 ***************************************************************************/
void
masscan_command_line(struct Masscan *masscan, int argc, char *argv[])
{
    int i;
    unsigned name_length;

    for (i=1; i<argc; i++) {

        /*
         * -(-)name=value
         * -(-)name:value
         * -(-)name value
         */
        if (argv[i][0] == '-') {
            unsigned tmp_step = 1;
            /*true:double dashes, false:single dash*/
            if (argv[i][1]=='-')
                tmp_step++;

            const char *argname = argv[i] + tmp_step;
            char name2[64];
            const char *value;

            if (is_numable(argname)) {
                /* May exist by itself like a bool or take an additional
                 * numeric argument */

                /* Look for:
                 * --name=value
                 * --name:value */
                value = strchr(argname, '=');
                if (value == NULL)
                    value = strchr(&argv[i][2], ':');
                if (value) {
                    name_length = (unsigned)(value - argname);
                } else {
                    /* The next parameter contains the name */
                    if (i+1 < argc) {
                        value = argv[i+1];
                        if (isInteger(value) || isBoolean(value))
                            i++;
                        else
                            value = "";
                    } else
                        value = "";
                    name_length = (unsigned)strlen(argname);
                }

                /* create a copy of the name */
                if (name_length > sizeof(name2) - 1) {
                    fprintf(stderr, "%.*s: name too long\n", name_length, argname);
                    name_length = sizeof(name2) - 1;
                }
                memcpy(name2, argname, name_length);
                name2[name_length] = '\0';

                masscan_set_parameter(masscan, name2, value);
            } else {
                value = strchr(&argv[i][2], '=');
                if (value == NULL)
                    value = strchr(&argv[i][2], ':');
                if (value == NULL) {
                    if (is_singleton(argname))
                        value = "";
                    else
                        value = argv[++i];
                    name_length = (unsigned)strlen(argname);
                } else {
                    name_length = (unsigned)(value - argname);
                    value++;
                }

                if (i >= argc) {
                    fprintf(stderr, "%.*s: empty parameter\n", name_length, argname);
                    break;
                }

                if (name_length > sizeof(name2) - 1) {
                    fprintf(stderr, "%.*s: name too long\n", name_length, argname);
                    name_length = sizeof(name2) - 1;
                }

                memcpy(name2, argname, name_length);
                name2[name_length] = '\0';

                masscan_set_parameter(masscan, name2, value);
            }
            continue;
        }

        if (!isdigit(argv[i][0]) && argv[i][0] != ':' && argv[i][0] != '[') {
            fprintf(stderr, "FAIL: unknown command-line parameter \"%s\"\n", argv[i]);
            exit(1);
        }

        /* If parameter doesn't start with '-', assume it's an
         * IPv4 range
         */
        masscan_set_parameter(masscan, "range", argv[i]);
    }

    /*
     * If no other "scan type" found, then default to TCP
     */
    if (masscan->scan_type.udp == 0 && masscan->scan_type.sctp == 0
        && masscan->scan_type.ping == 0 && masscan->scan_type.arp == 0
        && masscan->scan_type.oproto == 0)
        masscan->scan_type.tcp = 1;
    
    /*
     * If "top-ports" specified, then add all those ports. This may be in
     * addition to any other ports
     */
    if (masscan->top_ports) {
        config_top_ports(masscan, masscan->top_ports);
    }
    if (masscan->shard.of > 1 && masscan->seed == 0) {
        fprintf(stderr, "[-] WARNING: --seed <num> is not specified\n    HINT: all shards must share the same seed\n");
    }
}

/***************************************************************************
 * Prints the current configuration to the command-line then exits.
 * Use#1: create a template file of all settable parameters.
 * Use#2: make sure your configuration was interpreted correctly.
 ***************************************************************************/
void
masscan_echo(struct Masscan *masscan, FILE *fp, unsigned is_echo_all)
{
    unsigned i;
    
    /*
     * NEW:
     * Print all configuration parameters
     */
    masscan->echo = fp;
    masscan->echo_all = is_echo_all;
    for (i=0; config_parameters[i].name; i++) {
        config_parameters[i].set(masscan, 0, 0);
    }
    masscan->echo = 0;
    masscan->echo_all = 0;
}


/***************************************************************************
 * Prints the list of CIDR to scan to the command-line then exits.
 * Use: provide this list to other tools. Unlike masscan -sL, it keeps
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
masscan_echo_cidr(struct Masscan *masscan, FILE *fp, unsigned is_echo_all)
{
    unsigned i;
    UNUSEDPARM(is_echo_all);

    masscan->echo = fp;

    /*
     * For all IPv4 ranges ...
     */
    for (i=0; i<masscan->targets.ipv4.count; i++) {

        /* Get the next range in the list */
        struct Range range = masscan->targets.ipv4.list[i];

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
    for (i=0; i<masscan->targets.ipv6.count; i++) {
        struct Range6 range = masscan->targets.ipv6.list[i];
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
int masscan_conf_contains(const char *x, int argc, char **argv)
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
mainconf_selftest()
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
    
        if (masscan_conf_contains("--nothing", argc, argv))
            goto failure;

        if (!masscan_conf_contains("--readscan", argc, argv))
            goto failure;
    }

    return 0;
failure:
    fprintf(stderr, "[+] selftest failure: config subsystem\n");
    return 1;
}


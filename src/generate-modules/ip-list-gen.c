#include "generate-modules.h"
#include "../xconf.h"
#include "../version.h"
#include "../util-data/fine-malloc.h"
#include "../target/target-cookie.h"
#include "../target/target-parse.h"
#include "../target/target-rangev4.h"
#include "../target/target-rangev6.h"
#include "../crypto/crypto-blackrock.h"

Generator IpListGen;

struct IpListConf {
    FILE            *fp;
    uint64_t         seed;
    ipaddress        ip;
    struct RangeList ports;
    uint64_t         index;
    uint64_t         count_ports;
    BlackRock        br_table;
    unsigned         rounds;
    unsigned         no_random : 1;
};

static struct IpListConf iplist_conf = {0};

static ConfRes SET_no_random(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    iplist_conf.no_random = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_rounds(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    iplist_conf.rounds = (unsigned)conf_parse_int(value);
    return Conf_OK;
}

static ConfRes SET_port(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    unsigned err = 0;
    rangelist_parse_ports(&iplist_conf.ports, value, &err, 0);
    if (err) {
        LOG(LEVEL_ERROR, "(list generator) invalid port: %s.\n", value);
        return Conf_ERR;
    }
    rangelist_optimize(&iplist_conf.ports);
    iplist_conf.count_ports = rangelist_count(&iplist_conf.ports);

    return Conf_OK;
}

static ConfRes SET_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    iplist_conf.fp = fopen(value, "rb");
    if (iplist_conf.fp == NULL) {
        LOG(LEVEL_ERROR, "(stream generator) %s: %s\n", value, strerror(errno));
        return Conf_ERR;
    }
    return Conf_OK;
}

static ConfParam iplist_parameters[] = {
    {"default-port",
     SET_port,
     Type_ARG,
     {"port", "p", 0},
     "Specifies target ports for the input stream has no port info. like -p "
     "80. "
     "UDP ports can be specified, like --ports U:161,u:1024-1100. SCTP ports "
     "can be specified like --ports S:36412,s:38412, too.\n"
     "NOTE: We also support `--ports O:16` to present non-port number in range"
     " [0..65535] for some ScanModules."},
    {"ip-file",
     SET_file,
     Type_ARG,
     {"file", "f", 0},
     "Specifies a file as input stream. Default is stdin."},
    {"rounds",
     SET_rounds,
     Type_ARG,
     {"round", 0},
     "Specifies the number of round in blackrock algorithm for targets "
     "randomization in port range. It's 14 rounds in default to give "
     "a better statistical distribution with a low impact on scan rate."},
    {"no-random",
     SET_no_random,
     Type_FLAG,
     {"no-blackrock", "order", 0},
     "Generate port in natural order instead of using blackrock algorithm "
     "to randomize."},

    {0}};

bool iplist_init(const XConf *xconf, uint64_t *count_targets,
                 uint64_t *count_endpoints, bool *init_ipv4, bool *init_ipv6) {
    if (xconf->tx_thread_count != 1) {
        LOG(LEVEL_ERROR, "(list generator) supports only 1 tx thread.\n");
        return false;
    }

    if (iplist_conf.count_ports == 0) {
        LOG(LEVEL_HINT,
            "(list generator) use o:0 as default port for no specified.\n");
        unsigned err = 0;
        rangelist_parse_ports(&iplist_conf.ports, "o:0", &err, 0);
        if (err) {
            LOG(LEVEL_ERROR, "(list generator) add default port: %s.\n", "o:0");
            return false;
        }
        rangelist_optimize(&iplist_conf.ports);
        iplist_conf.count_ports = rangelist_count(&iplist_conf.ports);
    }

    if (!iplist_conf.fp) {
        iplist_conf.fp = stdin;
    }

    if (iplist_conf.rounds <= 0) {
        iplist_conf.rounds = XCONF_DFT_BLACKROCK_ROUNDS;
    }

    /*init all adapter in default*/
    *init_ipv4 = true;
    *init_ipv6 = true;

    iplist_conf.seed = xconf->seed;

    /*init blackrock only once for constant count of ip*ports*/
    if (!iplist_conf.no_random)
        blackrock1_init(&iplist_conf.br_table, iplist_conf.count_ports,
                        iplist_conf.seed, iplist_conf.rounds);

    return true;
}

bool iplist_hasmore(unsigned tx_index, uint64_t index) {

    if (iplist_conf.index < iplist_conf.count_ports &&
        iplist_conf.ip.version != 0)
        return true;

    /*add new ips*/
    char line[256];
    while (true) {
        char *s = fgets(line, sizeof(line), iplist_conf.fp);

        if (s == NULL) {
            if (ferror(iplist_conf.fp))
                LOG(LEVEL_DEBUG, "(list generator) error of list.\n");
            else if (feof(iplist_conf.fp))
                LOG(LEVEL_DEBUG, "(list generator) EOF of list.\n");
            return false;
        }

        /*absolute null line or the last line*/
        if (s[0] == '\n' || s[0] == '\r') {
            continue;
        }

        iplist_conf.ip = target_parse_ip(line);
        if (iplist_conf.ip.version == 0) {
            LOG(LEVEL_ERROR, "(list generator) invalid ip in address: %s",
                line);
            continue;
        } else
            break;
    }

    iplist_conf.index = 0;

    return true;
}

Target iplist_generate(unsigned tx_index, uint64_t index, uint64_t repeat,
                       struct source_t *src) {
    Target   target;
    uint64_t xXx = iplist_conf.index;
    uint64_t ck;

    /*Actually it is impossible*/
    while (xXx >= iplist_conf.count_ports) {
        xXx -= iplist_conf.count_ports;
    }

    if (!iplist_conf.no_random)
        xXx = blackrock1_shuffle(&iplist_conf.br_table, xXx);

    /**
     * Pick up target & source
     */
    target.ip_them   = iplist_conf.ip;
    target.port_them = rangelist_pick(&iplist_conf.ports, xXx);
    target.ip_proto  = get_actual_proto_port(&target.port_them);

    if (iplist_conf.ip.version == 4) {
        target.ip_me.version = 4;

        if (src->ipv4_mask > 1 || src->port_mask > 1) {
            ck = get_cookie_ipv4(
                (unsigned)(index + repeat), (unsigned)((index + repeat) >> 32),
                (unsigned)xXx, (unsigned)(xXx >> 32), iplist_conf.seed);
            target.port_me    = src->port + (ck & src->port_mask);
            target.ip_me.ipv4 = src->ipv4 + ((ck >> 16) & src->ipv4_mask);
        } else {
            target.port_me    = src->port;
            target.ip_me.ipv4 = src->ipv4;
        }
    } else {
        target.ip_me.version = 6;
        target.ip_me.ipv6    = src->ipv6;

        if (src->ipv6_mask > 1 || src->port_mask > 1) {
            ck = get_cookie_ipv4(
                (unsigned)(index + repeat), (unsigned)((index + repeat) >> 32),
                (unsigned)xXx, (unsigned)(xXx >> 32), iplist_conf.seed);
            target.port_me = src->port + (ck & src->port_mask);
            target.ip_me.ipv6.lo += (ck & src->ipv6_mask);
        } else {
            target.port_me = src->port;
        }
    }

    iplist_conf.index++;

    return target;
}

void iplist_close() {
    if (iplist_conf.fp != stdin) {
        fclose(iplist_conf.fp);
    }
    iplist_conf.fp = NULL;
    rangelist_rm_all(&iplist_conf.ports);
}

Generator IpListGen = {
    .name       = "ip-list",
    .params     = iplist_parameters,
    .short_desc = "Generates targets by IP list from stdin or file stream.",
    .desc = "IpList module generates target from stdin or file stream. The "
            "stream contains IP address in lines without target ports. So we "
            "need specify a  port range for all targets or use 'o:0' as "
            "default. For every IP from line, IpList will do random "
            "picking with port by blackrock algorithm.\n"
            "NOTE: IpList will blocking the tx thread while waiting the "
            "stream to be readable, this would break the rule of scan rate. "
            "However, the scan rate won't exceed the configured value.",

    .init_cb     = &iplist_init,
    .hasmore_cb  = &iplist_hasmore,
    .generate_cb = &iplist_generate,
    .close_cb    = &iplist_close,
};
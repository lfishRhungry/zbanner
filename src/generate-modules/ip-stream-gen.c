#include "generate-modules.h"

#include <string.h>

#include "../xconf.h"
#include "../target/target-cookie.h"
#include "../target/target-set.h"
#include "../target/target-rangev4.h"
#include "../target/target-rangev6.h"
#include "../target/target-rangeport.h"
#include "../crypto/crypto-blackrock.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"

Generator IpStreamGen;

struct IpStreamConf {
    FILE     *fp;
    uint64_t  seed;
    TargetSet targets;
    uint64_t  index;
    uint64_t  range_all;
    BlackRock br_table;
    unsigned  rounds;
    unsigned  no_random : 1;
};

static struct IpStreamConf ipstream_conf = {0};

static ConfRes SET_no_random(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    ipstream_conf.no_random = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_rounds(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    ipstream_conf.rounds = (unsigned)conf_parse_int(value);
    return Conf_OK;
}

static ConfRes SET_port(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    int err = targetset_add_port_str(&ipstream_conf.targets, value, 0);
    if (err) {
        LOG(LEVEL_ERROR, "(stream generator) invalid port: %s.\n", value);
        return Conf_ERR;
    }
    rangelist_optimize(&ipstream_conf.targets.ports);
    ipstream_conf.targets.count_ports =
        rangelist_count(&ipstream_conf.targets.ports);

    return Conf_OK;
}

static ConfRes SET_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    ipstream_conf.fp = fopen(value, "rb");
    if (ipstream_conf.fp == NULL) {
        LOG(LEVEL_ERROR, "(stream generator) %s: %s\n", value, strerror(errno));
        return Conf_ERR;
    }
    return Conf_OK;
}

static ConfParam ipstream_parameters[] = {
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
     "randomization in every IP/Port range. It's 14 rounds in default to give "
     "a better statistical distribution with a low impact on scan rate."},
    {"no-random",
     SET_no_random,
     Type_FLAG,
     {"no-blackrock", "order", 0},
     "Generate targets in natural order instead of using blackrock algorithm "
     "to randomize."},

    {0}};

bool ipstream_init(const XConf *xconf, uint64_t *count_targets,
                   uint64_t *count_endpoints, bool *init_ipv4,
                   bool *init_ipv6) {
    if (xconf->tx_thread_count != 1) {
        LOG(LEVEL_ERROR, "(stream generator) supports only 1 tx thread.\n");
        return false;
    }

    if (ipstream_conf.targets.count_ports == 0) {
        LOG(LEVEL_HINT,
            "(stream generator) use o:0 as default port for no specified.\n");
        targetset_add_port_str(&ipstream_conf.targets, "o:0", 0);
        rangelist_optimize(&ipstream_conf.targets.ports);
        ipstream_conf.targets.count_ports =
            rangelist_count(&ipstream_conf.targets.ports);
    }

    if (!ipstream_conf.fp) {
        ipstream_conf.fp = stdin;
    }

    if (ipstream_conf.rounds <= 0) {
        ipstream_conf.rounds = XCONF_DFT_BLACKROCK_ROUNDS;
    }

    /*init all adapter in default*/
    *init_ipv4 = true;
    *init_ipv6 = true;

    ipstream_conf.seed = xconf->seed;

    return true;
}

bool ipstream_hasmore(unsigned tx_index, uint64_t index) {

    if (ipstream_conf.index < ipstream_conf.range_all)
        return true;

    /*remove old ips */
    TargetSet *cur_tgt = &ipstream_conf.targets;
    targetset_rm_ip(cur_tgt);

    /*add new ips*/
    char line[256];
    while (true) {
        char *s = fgets(line, sizeof(line), ipstream_conf.fp);

        if (s == NULL) {
            if (ferror(ipstream_conf.fp))
                LOG(LEVEL_DEBUG, "(stream generator) error of stream.\n");
            else if (feof(ipstream_conf.fp))
                LOG(LEVEL_DEBUG, "(stream generator) EOF of stream.\n");
            return false;
        }

        /*absolute null line or the last line*/
        if (s[0] == '\n' || s[0] == '\r') {
            continue;
        }

        int err = targetset_add_ip_str(cur_tgt, line);
        if (err) {
            LOG(LEVEL_ERROR, "(stream generator) invalid ip in address: %s",
                line);
            continue;
        }

        /*update relevant info*/
        rangelist_optimize(&cur_tgt->ipv4);
        range6list_optimize(&cur_tgt->ipv6);

        cur_tgt->count_ipv4s    = rangelist_count(&cur_tgt->ipv4);
        cur_tgt->count_ipv6s    = range6list_count(&cur_tgt->ipv6);
        cur_tgt->ipv4_threshold = cur_tgt->count_ipv4s * cur_tgt->count_ports;

        /**
         * !only support 63-bit scans for every line
         */
        if (int128_bitcount(targetset_count(cur_tgt)) > 63) {
            LOG(LEVEL_ERROR,
                "(stream generator) range too large for scanning: "
                "%u-bits(>63).\n",
                int128_bitcount(targetset_count(cur_tgt)));
            continue;
        }

        break;
    }

    ipstream_conf.range_all =
        (cur_tgt->count_ipv4s + cur_tgt->count_ipv6s.lo) * cur_tgt->count_ports;
    ipstream_conf.index = 0;

    /*init blackrock again*/
    if (!ipstream_conf.no_random)
        blackrock1_init(&ipstream_conf.br_table, ipstream_conf.range_all,
                        ipstream_conf.seed, ipstream_conf.rounds);

    return true;
}

Target ipstream_generate(unsigned tx_index, uint64_t index, uint64_t repeat,
                         struct source_t *src) {
    Target     target;
    TargetSet *cur_tgt = &ipstream_conf.targets;
    uint64_t   xXx     = ipstream_conf.index;
    uint64_t   ck;

    /*Actually it is impossible*/
    while (xXx >= ipstream_conf.range_all) {
        xXx -= ipstream_conf.range_all;
    }

    if (!ipstream_conf.no_random)
        xXx = blackrock1_shuffle(&ipstream_conf.br_table, xXx);

    /**
     * Pick up target & source
     */
    if (xXx < cur_tgt->ipv4_threshold) {
        target.ip_them.version = 4;
        target.ip_me.version   = 4;

        target.ip_them.ipv4 =
            rangelist_pick(&cur_tgt->ipv4, xXx % cur_tgt->count_ipv4s);
        target.port_them =
            rangelist_pick(&cur_tgt->ports, xXx / cur_tgt->count_ipv4s);

        if (src->ipv4_mask > 1 || src->port_mask > 1) {
            ck = get_cookie_ipv4(
                (unsigned)(index + repeat), (unsigned)((index + repeat) >> 32),
                (unsigned)xXx, (unsigned)(xXx >> 32), ipstream_conf.seed);
            target.port_me    = src->port + (ck & src->port_mask);
            target.ip_me.ipv4 = src->ipv4 + ((ck >> 16) & src->ipv4_mask);
        } else {
            target.port_me    = src->port;
            target.ip_me.ipv4 = src->ipv4;
        }
    } else {
        xXx -= cur_tgt->ipv4_threshold;

        target.ip_them.version = 6;
        target.ip_me.version   = 6;

        target.ip_them.ipv6 =
            range6list_pick(&cur_tgt->ipv6, xXx % cur_tgt->count_ipv6s.lo);
        target.port_them =
            rangelist_pick(&cur_tgt->ports, xXx / cur_tgt->count_ipv6s.lo);

        target.ip_me.ipv6 = src->ipv6;

        if (src->ipv6_mask > 1 || src->port_mask > 1) {
            ck = get_cookie_ipv4(
                (unsigned)(index + repeat), (unsigned)((index + repeat) >> 32),
                (unsigned)xXx, (unsigned)(xXx >> 32), ipstream_conf.seed);
            target.port_me = src->port + (ck & src->port_mask);
            target.ip_me.ipv6.lo += (ck & src->ipv6_mask);
        } else {
            target.port_me = src->port;
        }
    }

    /**
     * Due to flexible port store method.
     */
    target.ip_proto = get_actual_proto_port(&target.port_them);

    ipstream_conf.index++;

    return target;
}

void ipstream_close() {
    if (ipstream_conf.fp != stdin) {
        fclose(ipstream_conf.fp);
    }
    ipstream_conf.fp = NULL;
    targetset_rm_all(&ipstream_conf.targets);
}

Generator IpStreamGen = {
    .name   = "ip-stream",
    .params = ipstream_parameters,
    .short_desc =
        "Generates targets by IP range list from stdin or file stream.",
    .desc = "IpStream module generates target from stdin or file stream. The "
            "stream contains IP range in lines without target ports. So we "
            "need specify a  port range for all targets or use 'o:0' as "
            "default. For every IP range(line), IpStream will do random "
            "picking with port by blackrock algorithm.\n"
            "NOTE: IpStream will blocking the tx thread while waiting the "
            "stream to be readable, this would break the rule of scan rate. "
            "However, the scan rate won't exceed the configured value.",

    .init_cb     = &ipstream_init,
    .hasmore_cb  = &ipstream_hasmore,
    .generate_cb = &ipstream_generate,
    .close_cb    = &ipstream_close,
};
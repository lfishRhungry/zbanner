#include "generate-modules.h"

#include "../xconf.h"
#include "../version.h"
#include "../target/target-rangeport.h"
#include "../crypto/crypto-blackrock.h"
#include "../target/target-cookie.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"

Generator BlackRockGen;

struct BlackRockConf {
    const TargetSet *targets;
    BlackRock        br_table; /*for multi tx threads*/
    uint64_t         count_ipv4;
    uint64_t         count_ipv6;
    uint64_t         range_all;
    uint64_t         range_ipv6;
    uint64_t         seed;
    unsigned         rounds;
    unsigned         no_random : 1;
};

static struct BlackRockConf blackrock_conf = {0};

static ConfRes SET_no_random(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    blackrock_conf.no_random = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_rounds(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    blackrock_conf.rounds = (unsigned)conf_parse_int(value);
    return Conf_OK;
}

static ConfParam blackrock_parameters[] = {
    {"rounds",
     SET_rounds,
     Type_ARG,
     {"round", 0},
     "Specifies the number of round in blackrock algorithm for targets "
     "randomization. It's 14 rounds in default to give a better statistical "
     "distribution with a low impact on scan rate."},
    {"no-random",
     SET_no_random,
     Type_FLAG,
     {"no-blackrock", "order", 0},
     "Generate targets in natural order instead of using blackrock algorithm "
     "to randomize."},

    {0}};

bool blackrock_init(const XConf *xconf, uint64_t *count_targets,
                    uint64_t *count_endpoints, bool *init_ipv4,
                    bool *init_ipv6) {
    blackrock_conf.targets = &xconf->targets;
    blackrock_conf.seed    = xconf->seed;

    /**
     * NOTE: Must has at least one ip and one port.
     */
    if (xconf->targets.count_ipv4s == 0 && xconf->targets.count_ipv6s.hi == 0 &&
        xconf->targets.count_ipv6s.lo == 0) {
        LOG(LEVEL_ERROR, "target IP address list empty.\n");
        return false;
    }

    uint64_t count_ports = rangelist_count(&xconf->targets.ports);
    if (count_ports == 0) {
        targetset_add_port_str((TargetSet *)(&xconf->targets), "o:0", 0);
        LOG(LEVEL_WARN, "(BlackRock) no ports were specified or remained, a "
                        "fake port o:0 was"
                        " specified automaticlly.\n");
        targetset_optimize((TargetSet *)&xconf->targets);
        count_ports = 1;
    }

    /**
     * !only support 63-bit scans
     */
    if (int128_bitcount(targetset_count(&xconf->targets)) > 63) {
        LOG(LEVEL_ERROR, "range is too large for scanning: %u-bits\n",
            int128_bitcount(targetset_count(&xconf->targets)));
        LOG(LEVEL_HINT, "range = target_count * endpoint_count\n");
        LOG(LEVEL_HINT, "max range is within 63-bits\n");
        return false;
    }

    /**
     * If the IP address range is very big, then require the
     * user apply an exclude range
     */
    uint64_t count_ips = rangelist_count(&xconf->targets.ipv4) +
                         range6list_count(&xconf->targets.ipv6).lo;
    if (count_ips > 1000000000ULL &&
        rangelist_count(&xconf->exclude.ipv4) == 0) {
        LOG(LEVEL_ERROR, "range too big, need confirmation\n");
        LOG(LEVEL_HINT,
            "to prevent accidents, at least one --exclude must be specified\n");
        LOG(LEVEL_HINT,
            "use \"--exclude 255.255.255.255\" as a simple confirmation\n");
        return false;
    }

    /**
     * Count target info
     */
    *count_targets   = count_ips;
    *count_endpoints = count_ports;
    *init_ipv4       = targetset_has_any_ipv4(&xconf->targets);
    *init_ipv6       = targetset_has_any_ipv6(&xconf->targets);

    blackrock_conf.count_ipv4 = rangelist_count(&xconf->targets.ipv4);
    blackrock_conf.count_ipv6 = range6list_count(&xconf->targets.ipv6).lo;
    blackrock_conf.range_all  = count_ips * count_ports;
    blackrock_conf.range_ipv6 =
        blackrock_conf.count_ipv6 * rangelist_count(&xconf->targets.ports);

    /**
     * prepare blackrock algorithm
     */
    if (blackrock_conf.no_random)
        return true;

    if (blackrock_conf.rounds <= 0) {
        blackrock_conf.rounds = XCONF_DFT_BLACKROCK_ROUNDS;
    }

    blackrock1_init(&blackrock_conf.br_table, blackrock_conf.range_all,
                    xconf->seed, blackrock_conf.rounds);

    return true;
}

bool blackrock_hasmore(unsigned tx_index, uint64_t index) {
    if (index < blackrock_conf.range_all) {
        return true;
    }
    return false;
}

Target blackrock_generate(unsigned tx_index, uint64_t index, uint64_t repeat,
                          struct source_t *src) {
    Target   target;
    uint64_t xXx = index;
    uint64_t ck;

    while (xXx >= blackrock_conf.range_all) {
        xXx -= blackrock_conf.range_all;
    }

    if (!blackrock_conf.no_random)
        xXx = blackrock1_shuffle(&blackrock_conf.br_table, xXx);

    /**
     * Pick up target & source
     */
    if (xXx < blackrock_conf.range_ipv6) {
        target.ip_them.version = 6;
        target.ip_me.version   = 6;

        target.ip_them.ipv6 = range6list_pick(&blackrock_conf.targets->ipv6,
                                              xXx % blackrock_conf.count_ipv6);
        target.port_them    = rangelist_pick(&blackrock_conf.targets->ports,
                                             xXx / blackrock_conf.count_ipv6);

        target.ip_me.ipv6 = src->ipv6;

        if (src->ipv6_mask > 1 || src->port_mask > 1) {
            ck = get_cookie_ipv4(
                (unsigned)(index + repeat), (unsigned)((index + repeat) >> 32),
                (unsigned)xXx, (unsigned)(xXx >> 32), blackrock_conf.seed);
            target.port_me = src->port + (ck & src->port_mask);
            target.ip_me.ipv6.lo += (ck & src->ipv6_mask);
        } else {
            target.port_me = src->port;
        }
    } else {
        xXx -= blackrock_conf.range_ipv6;

        target.ip_them.version = 4;
        target.ip_me.version   = 4;

        target.ip_them.ipv4 = rangelist_pick(&blackrock_conf.targets->ipv4,
                                             xXx % blackrock_conf.count_ipv4);
        target.port_them    = rangelist_pick(&blackrock_conf.targets->ports,
                                             xXx / blackrock_conf.count_ipv4);

        if (src->ipv4_mask > 1 || src->port_mask > 1) {
            ck = get_cookie_ipv4(
                (unsigned)(index + repeat), (unsigned)((index + repeat) >> 32),
                (unsigned)xXx, (unsigned)(xXx >> 32), blackrock_conf.seed);
            target.port_me    = src->port + (ck & src->port_mask);
            target.ip_me.ipv4 = src->ipv4 + ((ck >> 16) & src->ipv4_mask);
        } else {
            target.port_me    = src->port;
            target.ip_me.ipv4 = src->ipv4;
        }
    }

    /**
     * Due to flexible port store method.
     */
    target.ip_proto = get_actual_proto_port(&target.port_them);

    return target;
}

Generator BlackRockGen = {
    .name       = "blackrock",
    .params     = blackrock_parameters,
    .short_desc = "Default GenerateModule for randomizing scan targets(both "
                  "IPs and ports).",
    .desc =
        "BlackRock module randomizes ip*port that user set through commandline "
        "or file and generates ip:port in a dispersed way to reduce the "
        "pressure"
        " of target networks. It's the most classic permutation way from "
        "Masscan."
        " BlackRock implements an encryption algorithm based on DES and "
        "shuffles"
        " the index in stateless.\n"
        "NOTE1: BlackRock is the default generator of " XTATE_NAME_TITLE_CASE
        " if"
        " no other generator was specified.\n"
        "NOTE2: BlackRock generates targets in product of ip*port. So it cannot"
        " keep any relation between ip and port.",

    .init_cb     = &blackrock_init,
    .hasmore_cb  = &blackrock_hasmore,
    .generate_cb = &blackrock_generate,
    .close_cb    = &generate_close_nothing,
};
#include "generate-modules.h"
#include "../xconf.h"
#include "../version.h"
#include "../util-data/fine-malloc.h"
#include "../target/target-cookie.h"
#include "../target/target-parse.h"

Generator IpStreamGen;

struct IpStreamConf {
    FILE     *f;
    uint64_t  seed;
    ipaddress next_ip;
    unsigned  port_them;
    unsigned  ip_proto;
    unsigned  port_is_set : 1;
};

static struct IpStreamConf ipstream_conf = {0};

static ConfRes SET_port(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    unsigned         is_error = 0;
    struct RangeList ports    = {0};
    rangelist_parse_ports(&ports, value, &is_error, 0);
    if (is_error) {
        LOG(LEVEL_ERROR, "(stream generator) invalid port: %s.\n", value);
        return Conf_ERR;
    }
    if (ports.count != 1) {
        LOG(LEVEL_ERROR, "(stream generator) only support 1 default port.\n");
        return Conf_ERR;
    }

    ipstream_conf.port_them = ports.list->begin;
    ipstream_conf.ip_proto  = get_actual_proto_port(&(ipstream_conf.port_them));
    ipstream_conf.port_is_set = 1;
    return Conf_OK;
}

static ConfRes SET_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    ipstream_conf.f = fopen(value, "rb");
    if (ipstream_conf.f == NULL) {
        LOG(LEVEL_ERROR, "(stream generator) %s: %s\n", value, strerror(errno));
        return Conf_ERR;
    }
    return Conf_OK;
}

static ConfParam ipstream_parameters[] = {
    {"default-port",
     SET_port,
     Type_NONE,
     {"port", "p", 0},
     "Specifies a port as default if the input stream has no port info. A "
     "single port can be specified, like -p 80. UDP ports can be specified, "
     "like --ports U:161,u:1024-1100. SCTP ports can be specified like --ports "
     "S:36412,s:38412, too.\n"
     "NOTE: We also support `--ports O:16` to present non-port number in range"
     " [0..65535] for some ScanModules."},
    {"ip-file",
     SET_file,
     Type_NONE,
     {"file", "f", 0},
     "Specifies a file as ip stream."},

    {0}};

bool ipstream_init(const XConf *xconf, uint64_t *count_targets,
                   uint64_t *count_endpoints, bool *init_ipv4,
                   bool *init_ipv6) {
    if (xconf->tx_thread_count != 1) {
        LOG(LEVEL_ERROR, "(stream generator) supports only 1 tx thread.\n");
        return false;
    }

    if (!ipstream_conf.port_is_set) {
        LOG(LEVEL_HINT,
            "(stream generator) use o:0 as default port for no specified.\n");
        SET_port(NULL, "p", "o:0");
    }

    if (!ipstream_conf.f) {
        ipstream_conf.f = stdin;
    }

    *init_ipv4         = true; /*only use ipv4 adapter in default*/
    ipstream_conf.seed = xconf->seed;

    return true;
}

bool ipstream_hasmore(unsigned tx_index, uint64_t index) {
    /*use version of next ip to indicate that the next ip exists and is valid*/
    if (ipstream_conf.next_ip.version != 0)
        return true;

    char line[256];
    while (true) {
        char *s = fgets(line, sizeof(line), ipstream_conf.f);

        if (s == NULL) {
            if (ferror(ipstream_conf.f))
                LOG(LEVEL_DEBUG, "(stream generator) error of stream.\n");
            else if (feof(ipstream_conf.f))
                LOG(LEVEL_DEBUG, "(stream generator) EOF of stream.\n");
            return false;
        }

        ipstream_conf.next_ip = targetip_parse_ip(line);
        if (ipstream_conf.next_ip.version == 0) {
            LOG(LEVEL_ERROR, "(stream generator) invalid address: %s", line);
            continue;
        } else
            break;
    }

    return true;
}

Target ipstream_generate(unsigned tx_index, uint64_t index, uint64_t repeat,
                         struct source_t *src) {
    Target target;

    /**
     * Pick up target & source
     */
    target.ip_them   = ipstream_conf.next_ip;
    target.port_them = ipstream_conf.port_them;
    target.ip_proto  = ipstream_conf.ip_proto;

    if (ipstream_conf.next_ip.version == 6) {
        target.ip_me.version = 6;

        target.ip_me.ipv6 = src->ipv6;

        if (src->ipv6_mask > 1 || src->port_mask > 1) {
            target.port_me = src->port + (index & src->port_mask);
            target.ip_me.ipv6.lo += (index & src->ipv6_mask);
        } else {
            target.port_me = src->port;
        }
    } else {
        target.ip_me.version = 4;

        if (src->ipv4_mask > 1 || src->port_mask > 1) {
            target.port_me    = src->port + (index & src->port_mask);
            target.ip_me.ipv4 = src->ipv4 + ((index >> 16) & src->ipv4_mask);
        } else {
            target.port_me    = src->port;
            target.ip_me.ipv4 = src->ipv4;
        }
    }

    /*make next ip invalid*/
    ipstream_conf.next_ip.version = 0;

    return target;
}

void ipstream_close() {
    if (ipstream_conf.f != stdin) {
        fclose(ipstream_conf.f);
    }
}

Generator IpStreamGen = {
    .name   = "ip-stream",
    .params = ipstream_parameters,
    .short_desc =
        "Generates targets by single-IP lists from stdin or file stream.",
    .desc = "IpStream module generates target from stdin or file stream. The "
            "stream contains single-IP lines without ports. So we need specify "
            "only one target port for all targets or use 'o:0' as default.",

    .init_cb     = &ipstream_init,
    .hasmore_cb  = &ipstream_hasmore,
    .generate_cb = &ipstream_generate,
    .close_cb    = &ipstream_close,
};
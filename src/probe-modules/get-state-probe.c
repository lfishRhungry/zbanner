#include <string.h>
#include <stdio.h>

#include "probe-modules.h"
#include "../util-data/safe-string.h"
#include "../output-modules/output-modules.h"
#include "../util-out/logger.h"

#define GET_STATE_PAYLOAD "GET / HTTP/1.0\r\n\r\n"

/*for internal x-ref*/
extern struct ProbeModule GetStateProbe;

struct GetStateConf {
    unsigned get_whole_page:1;
};

static struct GetStateConf getstate_conf = {0};


static enum ConfigRes SET_whole_page(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    getstate_conf.get_whole_page = parseBoolean(value);

    return Conf_OK;
}

static struct ConfigParam getstate_parameters[] = {
    {
        "whole-page",
        SET_whole_page,
        Type_BOOL,
        {"whole", 0},
        "Get the whole page before connection timeout, not just the banner."
    },

    {0}
};

static bool getstate_global_init(const struct Xconf *xconf)
{
    LOG(LEVEL_WARN, "(GetState Probe global initing) >>>\n");
    return true;
}

static void getstate_close()
{
    LOG(LEVEL_WARN, "(GetState Probe closing) >>>\n");
}

static bool
getstate_conn_init(struct ProbeState *state, struct ProbeTarget *target)
{
    LOG(LEVEL_WARN, "(GetState Probe conn initing) >>>\n");
    return true;
}

static void
getstate_conn_close(struct ProbeState *state, struct ProbeTarget *target)
{
    LOG(LEVEL_WARN, "(GetState Probe conn closing) >>>\n");
}

static void
getstate_make_hello(
    struct DataPass *pass,
    struct ProbeState *state,
    struct ProbeTarget *target)
{
    LOG(LEVEL_WARN, "(GetState Probe making hello) >>>\n");
    /*static data and don't close the conn*/
    datapass_set_data(pass, (unsigned char *)GET_STATE_PAYLOAD,
        strlen(GET_STATE_PAYLOAD), 0);
}

static unsigned
getstate_parse_response(
    struct DataPass *pass,
    struct ProbeState *state,
    struct Output *out,
    struct ProbeTarget *target,
    const unsigned char *px,
    unsigned sizeof_px)
{
    LOG(LEVEL_WARN, "(GetState Probe parsing response) >>>\n");
    if (state->state) return 0;

    if (!getstate_conf.get_whole_page) {
        state->state   = 1;
        pass->is_close = 1;
    }

    struct OutputItem item = {
        .ip_proto  = target->ip_proto,
        .level     = OP_SUCCESS,
        .ip_them   = target->ip_them,
        .ip_me     = target->ip_me,
        .port_them = target->port_them,
        .port_me   = target->port_me,
    };

    dach_append_normalized(&item.report, "banner", px, sizeof_px);

    output_result(out, &item);

    return 0;
}

struct ProbeModule GetStateProbe = {
    .name       = "get-state",
    .type       = ProbeType_STATE,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .hello_wait = 0,
    .params     = getstate_parameters,
    .desc =
        "GetState Probe sends target port a simple HTTP HTTP Get request:\n"
        "    `GET / HTTP/1.0\\r\\n\\r\\n`\n"
        "And could get a simple result from http server fastly. GetState is the "
        "state version of GetRequest Probe for testing ScanModules that needs a"
        " probe of state type.",
    .init_cb                    = &getstate_global_init,
    .conn_init_cb                      = &getstate_conn_init,
    .make_hello_cb                     = &getstate_make_hello,
    .parse_response_cb                 = &getstate_parse_response,
    .conn_close_cb                     = &getstate_conn_close,
    .close_cb                          = &getstate_close,
};
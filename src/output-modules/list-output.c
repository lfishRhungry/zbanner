#include "output-modules.h"

#include "../util-out/logger.h"
#include "../pixie/pixie-file.h"

static const char fmt_host[]       = "%s";
static const char fmt_port[]       = " %s%u";

extern struct OutputModule ListOutput; /*for internal x-ref*/

static FILE *file;

struct ListConf {
    unsigned no_port:1;
};

static struct ListConf list_conf = {0};

static enum ConfigRes SET_no_port(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    list_conf.no_port = parseBoolean(value);

    return Conf_OK;
}

static struct ConfigParam list_parameters[] = {
    {
        "no-port",
        SET_no_port,
        Type_BOOL,
        {0},
        "Just output IP list in any time.\n"
        "NOTE: No deduplicating will be used for IP."
    },
    {0}
};

static bool
list_init(const struct Output *out)
{

    int err = pixie_fopen_shareable(
        &file, out->output_filename, out->is_append);

    if (err != 0 || file == NULL) {
        LOG(LEVEL_ERROR, "[-] ListOutput: could not open file %s for %s.\n",
            out->output_filename, out->is_append?"appending":"writing");
        perror(out->output_filename);
        return false;
    }

    return true;
}

static void
list_result(struct OutputItem *item)
{
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->ip_them);

    bool output_port = (item->ip_proto==IP_PROTO_TCP
        || item->ip_proto==IP_PROTO_UDP || item->ip_proto==IP_PROTO_SCTP);

    int err = 0;

    err = fprintf(file, fmt_host, ip_them_fmt.string);

    if (err<0) goto error;

    if (output_port && !list_conf.no_port) {
        switch (item->ip_proto) {
            case IP_PROTO_TCP:
                err = fprintf(file, fmt_port, "", item->port_them);
                break;
            case IP_PROTO_UDP:
                err = fprintf(file, fmt_port, "u:", item->port_them);
                break;
            case IP_PROTO_SCTP:
                err = fprintf(file, fmt_port, "s:", item->port_them);
                break;
            default:
                err = fprintf(file, fmt_port, "o:", item->port_them);
                break;
        }
        if (err<0) goto error;
    }

    err = fprintf(file, "\n");
    if (err<0) goto error;

    return;

error:
    LOG(LEVEL_ERROR, "[-] ListOutput: could not write result to file.\n");
}

static void
list_close(const struct Output *out)
{
    fflush(file);
    fclose(file);
}

struct OutputModule ListOutput = {
    .name               = "list",
    .need_file          = 1,
    .params             = list_parameters,
    .init_cb            = &list_init,
    .result_cb          = &list_result,
    .close_cb           = &list_close,
    .desc =
        "ListOutput save results just in \"IP port\" format to specified file "
        "without any other information.",
};
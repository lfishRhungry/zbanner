#include <string.h>

#include "probe-modules.h"
#include "../proto/proto-http-maker.h"
#include "../proto/proto-http-parser.h"
#include "../util-data/fine-malloc.h"
#include "../crypto/crypto-base64.h"

struct HelloConf {
    unsigned char *hello;
    size_t         hello_len;
};

static struct HelloConf hello_conf = {0};

static enum Config_Res SET_hello_string(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (hello_conf.hello)
        free(hello_conf.hello);

    hello_conf.hello_len = strlen(value);
    if (hello_conf.hello_len==0) {
        LOG(LEVEL_ERROR, "FAIL: Invalid hello string in base64 format.\n");
        return CONF_ERR;
    }

    hello_conf.hello     = CALLOC(1, hello_conf.hello_len);
    hello_conf.hello_len = base64_decode((char *)hello_conf.hello,
        hello_conf.hello_len, value, hello_conf.hello_len);

    return CONF_OK;
}

static enum Config_Res SET_hello_file(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (hello_conf.hello)
        free(hello_conf.hello);
    
    FILE *fp = fopen(value, "rb");
    if (fp==NULL) {
        LOG(LEVEL_ERROR, "[-]Failed to open file %s.\n", value);
        return CONF_ERR;
    }

    /**
     * We may specify a large size file accidently, so limit the size by a buf.
    */
    unsigned char buf[PROBE_PAYLOAD_MAX_LEN];
    size_t bytes_read = fread(buf, 1, PROBE_PAYLOAD_MAX_LEN, fp);
    if (bytes_read==0) {
        LOG(LEVEL_ERROR, "[-]Failed to read valid hello in file %s.\n", value);
        perror(value);
        fclose(fp);
        return CONF_ERR;
    }
    fclose(fp);


    hello_conf.hello_len = bytes_read;
    hello_conf.hello     = MALLOC(bytes_read);
    memcpy(hello_conf.hello, buf, bytes_read);

    return CONF_OK;
}

static struct ConfigParam hello_parameters[] = {
    {
        "string",
        SET_hello_string,
        F_NONE,
        {0},
        "Specifies a string in base64 format and set it as hello data after decoded."
    },
    {
        "file",
        SET_hello_file,
        F_NONE,
        {0},
        "Specifies a file and set the content of file as hello data."
    },
    
    {0}
};

/*for internal x-ref*/
extern struct ProbeModule HelloProbe;

static bool
hello_global_init(const struct Xconf *xconf)
{
    if (hello_conf.hello==NULL || hello_conf.hello_len==0) {
        LOG(LEVEL_ERROR, "[-]HelloProbe: No hello data specified.\n");
        return false;
    }

    return true;
}

static size_t
hello_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    memcpy(payload_buf, hello_conf.hello, hello_conf.hello_len);
    return hello_conf.hello_len;
}

static size_t
hello_get_payload_length(struct ProbeTarget *target)
{
    return hello_conf.hello_len;
}

static void
hello_close()
{
    if (hello_conf.hello) {
        free(hello_conf.hello);
        hello_conf.hello = NULL;
    }
    hello_conf.hello_len = 0;
}

struct ProbeModule HelloProbe = {
    .name       = "hello",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = hello_parameters,
    .desc =
        "HelloProbe use static content set by user as hello data and reports banner.",
    .global_init_cb                    = &hello_global_init,
    .make_payload_cb                   = &hello_make_payload,
    .get_payload_length_cb             = &hello_get_payload_length,
    .validate_response_cb              = NULL,
    .handle_response_cb                = &probe_just_report_banner,
    .close_cb                          = &hello_close,
};
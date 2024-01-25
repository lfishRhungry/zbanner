#include <string.h>

#include "../../xconf.h"
#include "lzr-http.h"


struct StatelessProbe LzrHttpProbe = {
    .name = "lzr-http",
    .type = Tcp_Probe,
    .help_text =
        "LzrHttp Probe sends an HTTP GET request and identifies HTTP service.\n",
    .global_init = NULL,
    .thread_init = NULL,
    .make_payload = &lzr_http_make_payload,
    .get_payload_length = &lzr_http_get_payload_length,
    .get_report_banner = &lzr_http_report_banner,
    .close = NULL
};

size_t
lzr_http_make_payload(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me,
    unsigned char *payload_buf, size_t buf_len)
{
    return snprintf((char *)payload_buf, buf_len, lzr_http_fmt,
        ipaddress_fmt(ip_them).string, port_them);
}

size_t
lzr_http_get_payload_length(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me)
{
    char tmp_str[160];
    return snprintf(tmp_str, 160, lzr_http_fmt,
        ipaddress_fmt(ip_them).string, port_them);
}

size_t
lzr_http_report_banner(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me,
    const unsigned char *banner, size_t banner_len,
    unsigned char *report_banner_buf, size_t buf_len)
{
    if (!strstr((const char *)banner, "HTTPS")
        &&
        (strstr((const char *)banner, "HTTP")
            || strstr((const char *)banner, "html")
            || strstr((const char *)banner, "HTML")
            || strstr((const char *)banner, "<h1>"))) {
        memcpy(report_banner_buf, "http", strlen("http"));
        return strlen("http");
    }

    return 0;
}
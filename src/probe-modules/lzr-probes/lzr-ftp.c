#include <string.h>

#include "../../xconf.h"
#include "lzr-ftp.h"
#include "../null-probe.h"


struct ProbeModule LzrFtpProbe = {
    .name = "lzr-ftp",
    .type = Tcp_Probe,
    .help_text =
        "LzrFtp Probe sends no data and identifies FTP service.\n",
    .global_init_cb = NULL,
    .thread_init_cb = NULL,
    .make_payload_cb = &make_no_payload,
    .get_payload_length_cb = &null_get_payload_length,
    .get_report_banner_cb = &lzr_ftp_report_banner,
    .close_cb = NULL
};

size_t
lzr_ftp_report_banner(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me,
    const unsigned char *banner, size_t banner_len,
    unsigned char *report_banner_buf, size_t buf_len)
{
    if (stristr((const char *)banner, "ftp")) {
        memcpy(report_banner_buf, "ftp", strlen("ftp"));
        return strlen("ftp");
    }

    /* This matching is like fallback condition in Nmap*/
    char tmp_str[4] = {banner[0], banner[1], banner[2], '\0'};
    if (strstr(tmp_str, "220")
        || strstr(tmp_str, "421")
        || strstr(tmp_str, "530")
        || strstr(tmp_str, "550")
        || strstr(tmp_str, "230")) {
        memcpy(report_banner_buf, "ftp", strlen("ftp"));
        return strlen("ftp");
    }

    return 0;
}
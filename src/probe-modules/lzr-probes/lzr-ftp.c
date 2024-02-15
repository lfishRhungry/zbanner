#include <string.h>

#include "../probe-modules.h"
#include "../../util/mas-safefunc.h"

/*for internal x-ref*/
extern struct ProbeModule LzrFtpProbe;

static int
lzr_ftp_handle_response(
    ipaddress ip_them, unsigned port_them,
    ipaddress ip_me, unsigned port_me,
    const unsigned char *px, unsigned sizeof_px,
    char *report, unsigned rpt_length)
{
    if (safe_memismem(px, sizeof_px, "ftp", strlen("ftp"))) {
        safe_strcpy(report, rpt_length, "ftp");
        return 0; /*no probe again*/
    }

    /* This matching is like fallback condition in Nmap*/
    char tmp_str[4] = {px[0], px[1], px[2], '\0'};
    if (strstr(tmp_str, "220")
        || strstr(tmp_str, "421")
        || strstr(tmp_str, "530")
        || strstr(tmp_str, "550")
        || strstr(tmp_str, "230")) {
        safe_strcpy(report, rpt_length, "ftp");
        return 0; /*no probe again*/
    }
    return 0; /*no probe again*/
}

struct ProbeModule LzrFtpProbe = {
    .name = "lzr-ftp",
    .type = ProbeType_TCP,
    .desc =
        "LzrFtp Probe sends no payload and identifies FTP service.\n",
    .global_init_cb = NULL,
    .rx_thread_init_cb = NULL,
    .tx_thread_init_cb = NULL,
    .make_payload_cb = NULL,
    .validate_response_cb = NULL,
    .handle_response_cb = &lzr_ftp_handle_response,
    .close_cb = NULL
};
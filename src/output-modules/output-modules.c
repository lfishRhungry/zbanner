#include <stdio.h>

#include "output-modules.h"

void
output_tmp(
    struct PreprocessedInfo * parsed,
    time_t timestamp, unsigned successed,
    const char *classification, const char *report)
{
    ipaddress ip_me = parsed->dst_ip;
    ipaddress ip_them = parsed->src_ip;
    unsigned port_me = parsed->port_dst;
    unsigned port_them = parsed->port_src;

    ipaddress_formatted_t ip_me_fmt = ipaddress_fmt(ip_me);
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(ip_them);

    char fmt[] = "Discovered %15s on port %5u is %s (%8s), report: %s";
    unsigned count = fprintf(stdout, fmt, ip_them_fmt.string, port_them,
        successed==SCAN_MODULE_SUCCESS_PACKET?"success":"failure",
        classification, report);
    
    if (count < 90)
            fprintf(stdout, "%.*s", (int)(89-count),
                    "                                          "
                    "                                          ");

    fprintf(stdout, "\n");
    fflush(stdout);
}
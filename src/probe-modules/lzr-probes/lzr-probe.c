#include "../../xconf.h"
#include "lzr-probe.h"

/*
 * LZR Probe will use `get_report_banner` funcs of all subprobes listed here
 * to match the banner and identify its service automaticly.
 * Subprobes' names always start with 'lzr-', and could be used as a normal
 * ProbeModule. It reports what service it identified out and will report
 * nothong if no service identified.
 * When they specified as subprobes in LZR probe with `--probe-args`, omit the
 * 'lzr-' prefix. LZR probe uses specified subprobe to send data, and matches
 * all subprobes to responsed banner. It could reports more than one service
 * or 'unknown' if nothing identified.
 * 
 * Subprobes of LZR are also StatelessProbes but its init and close callback
 * funcs will never be called. So leave all init and close funcs NULL.
 */

extern struct ProbeModule LzrWaitProbe;
extern struct ProbeModule LzrHttpProbe;
extern struct ProbeModule LzrFtpProbe;
//! ADD NEW LZR SUBPROBES HERE
//! ALSO ADD TO stateless-probes.c IF NEEDED



static struct ProbeModule *lzr_subprobes[] = {
    &LzrWaitProbe,
    &LzrHttpProbe,
    &LzrFtpProbe,
    //! ADD NEW LZR SUBPROBES HERE
    //! ALSO ADD TO stateless-probes.c IF NEEDED
};

static struct ProbeModule *specified_subprobe;

struct ProbeModule LzrProbe = {
    .name = "lzr",
    .type = Tcp_Probe,
    .help_text =
        "LZR Probe is an implement of service identification of LZR. It sends a\n"
        "specified LZR subprobe(handshake) and try to match with all LZR subprobes.\n"
        "Specify LZR subprobes by probe arguments:\n"
        "    `--probe-args http`\n",
        // "Note! LZR Probe will stop send next subprobe if no data responsed because\n",
        // "of no state.\n",
    .global_init_cb = &lzr_global_init,
    .thread_init_cb = NULL,
    .get_report_banner_cb = &lzr_report_banner,
    .close_cb = NULL,
    // make_payload_cb and get_paylaod_length will be set dynamicly in lzr_global_init.
};

static int lzr_global_init(const void *Xconf)
{
    const struct Xconf *xconf = Xconf;

    /*Use LzrWait if no subprobe specified*/
    if (!xconf->probe_module_args[0]) {
        specified_subprobe = &LzrWaitProbe;
        fprintf(stderr, "[-] Use default LzrWait as subprobe of LzrProbe because no subprobe was specified by --probe-args.\n");
    } else {
        char subprobe_name[LZR_SUBPROBE_NAME_LEN] = "lzr-";
        memcpy(subprobe_name+strlen(subprobe_name), xconf->probe_module_args,
            LZR_SUBPROBE_NAME_LEN-strlen(subprobe_name)-1);

        specified_subprobe = get_probe_module_by_name(subprobe_name);
        if (specified_subprobe == NULL) {
            return EXIT_FAILURE;
        }
    }

    LzrProbe.make_payload_cb = specified_subprobe->make_payload_cb;
    LzrProbe.get_payload_length_cb = specified_subprobe->get_payload_length_cb;

    return EXIT_SUCCESS;
}

static size_t
lzr_report_banner(ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me,
    const unsigned char *banner, size_t banner_len,
    unsigned char *report_banner_buf, size_t buf_len)
{
    /**
     * I think STATELESS_BANNER_MAX_LEN is long enough.
     * However I am tired while coding there.
    */
    unsigned char *buf_idx = report_banner_buf;
    size_t remain_len = buf_len;

    /*match specified subprobe first*/
    size_t len = specified_subprobe->get_report_banner_cb(ip_them, ip_me, port_them, port_me,
        banner, banner_len, report_banner_buf, buf_len);
    
    /**
     * We want to print much results like:
     *     pop3-smtp-http
    */
    buf_idx += len;
    if (len) {
        buf_idx[0] = '-';
        buf_idx++;
    }
    remain_len = buf_len - (buf_idx - report_banner_buf);
    
    /**
     * strcat every lzr subprobes match result
    */
    for (size_t i=0; i<sizeof(lzr_subprobes)/sizeof(struct ProbeModule*); i++) {
        if (lzr_subprobes[i] == specified_subprobe)
            continue;

        len = lzr_subprobes[i]->get_report_banner_cb(ip_them, ip_me, port_them, port_me,
            banner, banner_len, buf_idx, remain_len);

        buf_idx += len;
        if (len) {
            buf_idx[0] = '-';
            buf_idx++;
        }
        remain_len = buf_len - (buf_idx - report_banner_buf);
    }

    /*got nothing*/
    if (buf_idx==report_banner_buf) {
        memcpy(report_banner_buf, "unknown", strlen("unknown"));
        buf_idx += strlen("unknown");
    } else {
    /* truncat the last '-' */
        buf_idx--;
    }

    /* truncat the last '-' */
    return buf_idx-report_banner_buf;
}
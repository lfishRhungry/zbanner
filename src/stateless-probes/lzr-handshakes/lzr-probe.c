#include "../../masscan.h"
#include "lzr-probe.h"


extern struct StatelessProbe LzrWaitProbe;
extern struct StatelessProbe LzrHttpProbe;
extern struct StatelessProbe LzrFtpProbe;
//! ADD NEW LZR SUBPROBES HERE
//! ALSO ADD TO stateless-probes.c IF NEEDED



static struct StatelessProbe *lzr_subprobes[] = {
    &LzrWaitProbe,
    &LzrHttpProbe,
    &LzrFtpProbe,
    //! ADD NEW LZR SUBPROBES HERE
    //! ALSO ADD TO stateless-probes.c IF NEEDED
};

static struct StatelessProbe *specified_subprobe;

struct StatelessProbe LzrProbe = {
    .name = "lzr",
    .help_text =
        "LZR Probe is an implement of service identification of LZR. It sends a\n"
        "specified LZR subprobe(handshake) and try to match with all LZR subprobes.\n"
        "Specify LZR subprobes by probe arguments:\n"
        "    `--probe-args http`\n",
        // "Note! LZR Probe will stop send next subprobe if no data responsed because\n",
        // "of no state.\n",
    .global_init = &lzr_global_init,
    .thread_init = NULL,
    .get_report_banner = &lzr_report_banner,
    .close = NULL,
    // make_payload and get_paylaod_length will be set dynamicly in lzr_global_init.
};

static int lzr_global_init(const void *Masscan)
{
    const struct Masscan *masscan = Masscan;

    /*Use LzrWait if no subprobe specified*/
    if (!masscan->stateless_probe_args[0]) {
        specified_subprobe = &LzrWaitProbe;
        fprintf(stderr, "[-] Use default LzrWait as subprobe of LzrProbe because no subprobe was specified by --probe-args.\n");
    } else {
        char subprobe_name[LZR_SUBPROBE_NAME_LEN] = "lzr-";
        memcpy(subprobe_name+strlen(subprobe_name), masscan->stateless_probe_args,
            LZR_SUBPROBE_NAME_LEN-strlen(subprobe_name)-1);

        specified_subprobe = get_stateless_probe(subprobe_name);
        if (specified_subprobe == NULL) {
            return EXIT_FAILURE;
        }
    }

    LzrProbe.make_payload = specified_subprobe->make_payload;
    LzrProbe.get_payload_length = specified_subprobe->get_payload_length;

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
    size_t len = specified_subprobe->get_report_banner(ip_them, ip_me, port_them, port_me,
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
    for (size_t i=0; i<sizeof(lzr_subprobes)/sizeof(struct StatelessProbe*); i++) {
        if (lzr_subprobes[i] == specified_subprobe)
            continue;

        len = lzr_subprobes[i]->get_report_banner(ip_them, ip_me, port_them, port_me,
            banner, banner_len, buf_idx, remain_len);

        buf_idx += len;
        if (len) {
            buf_idx[0] = '-';
            buf_idx++;
        }
        remain_len = buf_len - (buf_idx - report_banner_buf);
    }

    /* truncat the last '-' */
    return buf_idx==report_banner_buf?0:buf_idx-report_banner_buf-1;
}
#include "xtatus.h"
#include "../pixie/pixie-timer.h"
#include "../util-misc/cross.h"
#include "../globals.h"
#include "../util-data/safe-string.h"

#include <stdio.h>


void
xtatus_print(
    struct Xtatus *xtatus,
    uint64_t       count,
    uint64_t       max_count,
    double         pps,
    double         tx_q_ratio,
    double         rx_q_ratio,
    uint64_t       total_successed,
    uint64_t       total_failed,
    uint64_t       total_info,
    uint64_t       total_sent,
    uint64_t       total_tm_event,
    uint64_t       total_tcb,
    uint64_t       exiting,
    bool           json_status)
{
    const char         *fmt;
    double              elapsed_time;
    double              rate;
    double              now;
    double              percent_done;
    double              time_remaining;
    uint64_t            current_successed     = 0;
    uint64_t            current_sent          = 0;
    double              successed_rate        = 0.0;
    double              sent_rate             = 0.0;
    double              kpps                  = pps / 1000;

    const char* json_fmt_infinite =
    "{"
        "\"state\":\"*\","
        "\"rate\":"
        "{"
            "\"kpps\":%.2f,"
            "\"pps\":%.2f,"
            "\"sent ps\":%.0f,"
            "\"successed ps\":%.0f,"
        "},"
        "\"sent\":%" PRIu64 ","
        "\"tm_event\":%" PRIu64 ","
        "\"tcb\":%" PRIu64 ","
        "\"tx_q\":%.2f%%,"
        "\"rx_q\":%.2f%%"
    "}\n";
    
    const char *json_fmt_waiting = 
    "{"
        "\"state\":\"waiting\","
        "\"rate\":"
        "{"
            "\"kpps\":%.2f,"
            "\"pps\":%.2f"
        "},"
        "\"progress\":"
        "{"
            "\"percent\":%.2f,"
            "\"seconds\":%d,"
            "\"successed\":%" PRIu64 ","
            "\"failed\":%" PRIu64 ","
            "\"info\":%" PRIu64 ","
            "\"tm_event\":%" PRIu64 ","
            "\"tcb\":%" PRIu64 ","
            "\"tx_q\":%.2f%%,"
            "\"rx_q\":%.2f%%,"
            "\"transmit\":"
            "{"
                "\"sent\":%" PRIu64 ","
                "\"total\":%" PRIu64 ","
                "\"remaining\":%" PRIu64
            "}" 
        "}"
    "}\n";

    const char *json_fmt_running = 
    "{"
        "\"state\":\"running\","
        "\"rate\":"
        "{"
            "\"kpps\":%.2f,"
            "\"pps\":%.2f"
        "},"
        "\"progress\":"
        "{"
            "\"percent\":%.2f,"
            "\"eta\":"
            "{"
                "\"hours\":%u,"
                "\"mins\":%u,"
                "\"seconds\":%u"
            "},"
            "\"transmit\":"
            "{"
                "\"sent\":%" PRIu64 ","
                "\"total\":%" PRIu64 ","
                "\"remaining\":%" PRIu64
            "}," 
            "\"successed\":%" PRIu64 ","
            "\"failed\":%" PRIu64 ","
            "\"info\":%" PRIu64 ","
            "\"tm_event\":%" PRIu64
            "\"tcb\":%" PRIu64 ","
            "\"tx_q\":%.2f%%,"
            "\"rx_q\":%.2f%%"
        "}"
    "}\n";

    /*
     * ####  FUGGLY TIME HACK  ####
     *
     * PF_RING doesn't timestamp packets well, so we can't base time from
     * incoming packets. Checking the time ourself is too ugly on per-packet
     * basis. Therefore, we are going to create a global variable that keeps
     * the time, and update that variable whenever it's convenient. This
     * is one of those convenient places.
     */
    global_now = time(0);


    /* Get the time. NOTE: this is CLOCK_MONOTONIC_RAW on Linux, not
     * wall-clock time. */
    now = (double)pixie_gettime();

    /* Figure how many SECONDS have elapsed, in a floating point value.
     * Since the above timestamp is in microseconds, we need to
     * shift it by 1-million
     */
    elapsed_time = (now - xtatus->last.clock)/1000000.0;
    if (elapsed_time <= 0)
        return;

    /* Figure out the "packets-per-second" number, which is just:
     *
     *  rate = packets_sent / elapsed_time;
     */
    rate = (count - xtatus->last.count)*1.0/elapsed_time;

    /*
     * Smooth the number by averaging over the last 8 seconds
     */
     xtatus->last_rates[xtatus->last_count++ & 0x7] = rate;
     rate =       xtatus->last_rates[0]
                + xtatus->last_rates[1]
                + xtatus->last_rates[2]
                + xtatus->last_rates[3]
                + xtatus->last_rates[4]
                + xtatus->last_rates[5]
                + xtatus->last_rates[6]
                + xtatus->last_rates[7]
                ;
    rate /= 8;
    /*if (rate == 0)
        return;*/

    /*
     * Calculate "percent-done", which is just the total number of
     * packets sent divided by the number we need to send.
     */
    percent_done = (double)(count*100.0/max_count);


    /*
     * Calculate the time remaining in the scan
     */
    time_remaining  = (1.0 - percent_done/100.0) * (max_count / rate);

    /*
     * some other stats
     */
    if (total_successed) {
        current_successed           = total_successed - xtatus->total_successed;
        xtatus->total_successed     = total_successed;
        successed_rate              = (1.0*current_successed)/elapsed_time;
    }
    if (total_sent) {
        current_sent                = total_sent - xtatus->total_sent;
        xtatus->total_sent          = total_sent;
        sent_rate                   = (1.0*current_sent)/elapsed_time;
    }

    /*
     * Print the message to <stderr> so that <stdout> can be redirected
     * to a file (<stdout> reports what systems were found).
     */

    if (xtatus->is_infinite) {
        if (json_status == 1) {
            fmt = json_fmt_infinite;

            fprintf(stderr,
                    fmt,
                    kpps,
                    pps,
                    sent_rate,
                    successed_rate,
                    count,
                    total_tm_event,
                    total_tcb,
                    tx_q_ratio,
                    rx_q_ratio);
        } else {
            fmt = "rate:%6.2f-kpps, sent/s=%.0f, [+]/s=%.0f" PRIu64;

            fprintf(stderr,
                    fmt,
                    kpps,
                    sent_rate,
                    tx_q_ratio,
                    rx_q_ratio,
                    successed_rate);

            if (xtatus->print_ft_event) {
                fmt = ", tm_event=%6$" PRIu64;
                fprintf(stderr, fmt, total_tm_event);
            }

            if (xtatus->print_tcb) {
                fmt = ", tcb=%6$" PRIu64;
                fprintf(stderr, fmt, total_tcb);
            }

            if (xtatus->print_queue) {
                fmt = ", %5.2f%%-tx_q, %5.2f%%-rx_q";
                fprintf(stderr, fmt, tx_q_ratio, rx_q_ratio);
            }

            fprintf(stderr, "                \r");
        
        }

    } else {
        if (is_tx_done) {
            if (json_status == 1) {
                fmt = json_fmt_waiting;

                fprintf(stderr,
                        fmt,
                        pps/1000.0,
                        pps,
                        percent_done,
                        (int)exiting,
                        total_successed,
                        total_failed,
                        total_info,
                        total_tm_event,
                        total_tcb,
                        tx_q_ratio,
                        rx_q_ratio,
                        count,
                        max_count,
                        max_count-count);
            } else {
                fmt = "rate:%6.2f-kpps, %5.2f%% done, waiting %d-secs, [+]=%" PRIu64 ", [x]=%" PRIu64;

                fprintf(stderr,
                        fmt,
                        pps/1000.0,
                        percent_done,
                        (int)exiting,
                        tx_q_ratio,
                        rx_q_ratio,
                        total_successed,
                        total_failed);

                if (xtatus->print_info_num) {
                    fmt = ", [*]=%" PRIu64;
                    fprintf(stderr, fmt, total_info);
                }

                if (xtatus->print_ft_event) {
                    fmt = ", tm_event=%" PRIu64;
                    fprintf(stderr, fmt, total_tm_event);
                }

                if (xtatus->print_tcb) {
                    fmt = ", tcb=%" PRIu64;
                    fprintf(stderr, fmt, total_tcb);
                }

                if (xtatus->print_queue) {
                    fmt = ", %5.2f%%-tx_q, %5.2f%%-rx_q";
                    fprintf(stderr, fmt, tx_q_ratio, rx_q_ratio);
                }

                fprintf(stderr, "       \r");

            }

        } else {
            if (json_status == 1) {
                fmt = json_fmt_running;

                fprintf(stderr,
                    fmt,
                    pps/1000.0,
                    pps,
                    percent_done,
                    (unsigned)(time_remaining/60/60),
                    (unsigned)(time_remaining/60)%60,
                    (unsigned)(time_remaining)%60,
                    count,
                    max_count,
                    max_count-count,
                    total_successed,
                    total_failed,
                    total_info,
                    total_tm_event,
                    total_tcb,
                    tx_q_ratio,
                    rx_q_ratio);
            } else {
                fmt = "rate:%6.2f-kpps, %5.2f%% done,%4u:%02u:%02u remaining, [+]=%" PRIu64 ", [x]=%" PRIu64;

                fprintf(stderr,
                    fmt,
                    pps/1000.0,
                    percent_done,
                    (unsigned)(time_remaining/60/60),
                    (unsigned)(time_remaining/60)%60,
                    (unsigned)(time_remaining)%60,
                    tx_q_ratio,
                    rx_q_ratio,
                    total_successed,
                    total_failed);

                if (xtatus->print_info_num) {
                    fmt = ", [*]=%" PRIu64;
                    fprintf(stderr, fmt, total_info);
                }

                if (xtatus->print_ft_event) {
                    fmt = ", tm_event=%" PRIu64;
                    fprintf(stderr, fmt, total_tm_event);
                }

                if (xtatus->print_tcb) {
                    fmt = ", tcb=%" PRIu64;
                    fprintf(stderr, fmt, total_tcb);
                }

                if (xtatus->print_queue) {
                    fmt = ", %5.2f%%-tx_q, %5.2f%%-rx_q";
                    fprintf(stderr, fmt, tx_q_ratio, rx_q_ratio);
                }

                fprintf(stderr, "       \r");
            }
        }
    }
    fflush(stderr);

    /*
     * Remember the values to be diffed against the next time around
     */
    xtatus->last.clock = now;
    xtatus->last.count = count;
}

/***************************************************************************
 ***************************************************************************/
void
xtatus_finish(struct Xtatus *xtatus)
{
    UNUSEDPARM(xtatus);
    fprintf(stderr,"\n");
}

/***************************************************************************
 ***************************************************************************/
void
xtatus_start(struct Xtatus *xtatus)
{
    memset(xtatus, 0, sizeof(*xtatus));
    xtatus->last.clock    = clock();
    xtatus->last.time     = time(0);
    xtatus->last.count    = 0;
}

#ifndef LIST_TARGETS_H
#define LIST_TARGETS_H

#include <stdio.h>

typedef struct XtateConf XConf;

/***************************************************************************
 * Prints IPs and ports in the targetsets of xconf in IP/Port pairs or in IPs
 * if only one port:
 *  10.0.0.64 443
 *  10.0.0.65 80
 *  10.0.0.1 u:53
 * Also can print relative AS info if `--out-as-info` is on.
 ***************************************************************************/
void listtargets_ip_port(XConf *xconf, FILE *fp);

/***************************************************************************
 * Prints each IP range in the targetsets of xconf in a CIDR if possible or
 * in a ranges:
 *  10.0.0.64/26
 *  10.0.0.128-10.0.0.130
 ***************************************************************************/
void listtargets_range(XConf *xconf, FILE *fp);

/***************************************************************************
 * Prints all IP range in the targetsets of xconf in CIDRs like:
 *  10.0.0.1/32
 *  10.0.0.2/31
 *  10.0.0.4/30
 *  10.0.0.8/29
 *  10.0.0.16/28
 *  10.0.0.32/27
 *  10.0.0.64/26
 *  10.0.0.128/25
 ***************************************************************************/
void listtargets_cidr(XConf *xconf, FILE *fp);

#endif

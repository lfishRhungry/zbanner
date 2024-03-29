/*
    Reads the 'nmap-service-probes' file.
 */
#ifndef SERVICE_PROBES_H
#define SERVICE_PROBES_H
#include <stdio.h>
#include <pcre.h>
#include "../massip/massip-rangesv4.h"

#define NMAP_IPPROTO_TCP    6
#define NMAP_IPPROTO_UDP   17


struct ServiceProbeMatch;

/*
 Exclude <port specification>
 Probe <protocol> <probename> <probestring>
 match <service> <pattern> [<versioninfo>]
 softmatch <service> <pattern>
 ports <portlist>
 sslports <portlist>
 totalwaitms <milliseconds>
 tcpwrappedms <milliseconds>
 rarity <value between 1 and 9>
 fallback <Comma separated list of probes>
 */
enum SvcP_RecordType {
    SvcP_Unknown,
    SvcP_Exclude,
    SvcP_Probe,
    SvcP_Match,
    SvcP_Softmatch,
    SvcP_Ports,
    SvcP_Sslports,
    SvcP_Totalwaitms,
    SvcP_Tcpwrappedms,
    SvcP_Rarity,
    SvcP_Fallback,
};

enum SvcV_InfoType {
    SvcV_Unknown,
    SvcV_ProductName,
    SvcV_Version,
    SvcV_Info,
    SvcV_Hostname,
    SvcV_OperatingSystem,
    SvcV_DeviceType,
    SvcV_CpeName,
};

struct ServiceVersionInfo {
    enum SvcV_InfoType                  type;
    char                               *value;
    struct ServiceVersionInfo          *next;
    unsigned                            is_a:1;
};

struct ServiceProbeFallback {
    char                               *name;
    struct NmapServiceProbe            *probe;
    struct ServiceProbeFallback        *next;
};

struct ServiceProbeMatch {
    struct ServiceProbeMatch           *next;
    char                               *service;
    char                               *regex;
    size_t                              regex_length;
    pcre                               *compiled_re;
    pcre_extra                         *compiled_extra;
    struct ServiceVersionInfo          *versioninfo;
    unsigned                            is_case_insensitive:1;
    unsigned                            is_include_newlines:1;
    unsigned                            is_softmatch:1;
};

struct NmapServiceProbe {
    char                               *name;
    char                               *hellostring;
    size_t                              hellolength;
    unsigned                            protocol;
    unsigned                            totalwaitms;
    unsigned                            tcpwrappedms;
    unsigned                            rarity;
    struct RangeList                    ports;
    struct RangeList                    sslports;
    struct ServiceProbeMatch           *match;
    struct ServiceProbeFallback        *fallback;
};

struct NmapServiceProbeList {
    struct NmapServiceProbe           **probes;
    struct RangeList                    exclude;
    unsigned                            count;
    unsigned                            max_slot;
    const char                         *filename;
    unsigned                            line_number;
};


struct NmapServiceProbeList *
nmapservice_read_file(const char *filename);

void
nmapservice_match_compile(struct NmapServiceProbeList * service_probes);

void
nmapservice_link_fallback(struct NmapServiceProbeList *list);

void
nmapservice_match_free(struct NmapServiceProbeList * service_probes);

void
nmapservice_free(struct NmapServiceProbeList *service_probes);

/**
 * Print to a file for testing purposes
 */
void
nmapservice_print_all(const struct NmapServiceProbeList *list, FILE *fp);

/**
 * @param service_probes loaded NmapServiceProbeList
 * @param idx_now index of probe have been used.
 * @param port_them port of target to match probe or 0 if ignoring port.
 * @param rarity rarity for filtering probe.
 * @param protocol NMAP_IPPROTO_TCP or NMAP_IPPROTO_UDP
 * @return next available tcp probe index or 0 if no available
*/
unsigned
nmapservice_next_probe_index(const struct NmapServiceProbeList *service_probes,
    unsigned idx_now, unsigned port_them, unsigned rarity, unsigned protocol);

struct NmapServiceProbe *
nmapservice_get_probe_by_name(struct NmapServiceProbeList *list,
    const char *name, unsigned protocol);

/**
 * Match service from matches in specified probe with fallback and null match.
 * Match result could be a softmatch.
 * @return matched struct from service_probes or NULL if not matched.
*/
struct ServiceProbeMatch *
nmapservice_match_service(
    const struct NmapServiceProbeList *service_probes,
    unsigned probe_idx,
    const unsigned char *payload,
    size_t payload_len,
    unsigned protocol);

#endif


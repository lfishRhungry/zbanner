/**
 * AS Query
 *
 * Load ip2asn-v4.tsv and/or ip2asn-v6.tsv file and search AS info for IP.
 *
 * AS files download link:
 *    https://iptoasn.com/data/ip2asn-v4.tsv.gz
 *    https://iptoasn.com/data/ip2asn-v6.tsv.gz

    Create by sharkocha 2024
 */
#ifndef AS_QUERY_H
#define AS_QUERY_H

#include "../target/target-ipaddress.h"

struct AS_Query;

struct AS_Info {
    unsigned asn;
    char    *country_code;
    char    *desc;
};

/**
 * @param filename_v4 name of ip2asn-v4 file or NULL.
 * @param filename_v6 name of ip2asn-v6 file or NULL.
 * NOTE: Only handle ip2asn files in standard format. Can only load one file.
 * @return struct AS_Query with loaded one or two ip2asn file. NULL if neither
 * one was loaded.
 */
struct AS_Query *as_query_new(const char *filename_v4, const char *filename_v6);

/**
 * @return get a struct AS_Info for searched IP. If no AS info searched out or
 * as_query is invalid, also can get an AS_Info with `null` info.
 */
const struct AS_Info as_query_search_ip(const struct AS_Query *as_query,
                                        const ipaddress        ip);

void as_query_destroy(struct AS_Query *as_query);

#endif
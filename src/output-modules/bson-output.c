#ifndef NOT_FOUND_BSON

#include "output-modules.h"
#include "bson-output.h"
#include "../version.h"

#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../pixie/pixie-file.h"

#include <bson/bson.h>

extern Output BsonOutput; /*for internal x-ref*/

static FILE *file;

static char format_time[32];

struct BsonConf {
    unsigned compact : 1;
};

static struct BsonConf bson_conf = {0};

static ConfRes SET_compact(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    bson_conf.compact = parse_str_bool(value);

    return Conf_OK;
}

static ConfParam bson_parameters[] = {
    {"compact-mode",
     SET_compact,
     Type_FLAG,
     {"compact", 0},
     "Record time, IP proto, IP addr and level field as compacted number type "
     "instead of string. This will reduce the size of the result file.\n"
     "NOTE: IPv4 addr will save as an int32 number. IPv6 addr will save as two"
     " int64 number. Level field will save to an int32 as 'information' for 0, "
     "'failure' for 1 and 'success' for 2. Time and IP proto will save as an "
     "int32 number,."},
    {0}};

static bool bsonout_init(const XConf *xconf, const OutConf *out) {
    /**
     * BSON is binary style, so print to stdout is nonsense.
     */

    int err =
        pixie_fopen_shareable(&file, out->output_filename, out->is_append);

    if (err != 0 || file == NULL) {
        LOG(LEVEL_ERROR, "BsonOutput: could not open file %s for %s.\n",
            out->output_filename, out->is_append ? "appending" : "writing");
        perror(out->output_filename);
        return false;
    }

    return true;
}

static void bsonout_result(OutItem *item) {
    bson_t *res_doc = bson_new();

    if (bson_conf.compact) {
        BSON_APPEND_DATE_TIME(res_doc, "time",
                              (uint64_t)item->timestamp * 1000);
        BSON_APPEND_INT32(res_doc, "level", item->level);
        BSON_APPEND_INT32(res_doc, "ip_proto", item->target.ip_proto);
        if (item->target.ip_them.version == 4) {
            BSON_APPEND_INT32(res_doc, "ip_them", item->target.ip_them.ipv4);
            BSON_APPEND_INT32(res_doc, "ip_me", item->target.ip_me.ipv4);
        } else {
            BSON_APPEND_INT64(res_doc, "ip_them_hi",
                              item->target.ip_them.ipv6.hi);
            BSON_APPEND_INT64(res_doc, "ip_them_lo",
                              item->target.ip_them.ipv6.lo);
            BSON_APPEND_INT64(res_doc, "ip_me_hi", item->target.ip_me.ipv6.hi);
            BSON_APPEND_INT64(res_doc, "ip_me_lo", item->target.ip_me.ipv6.lo);
        }
    } else {
        iso8601_time_str(format_time, sizeof(format_time), &item->timestamp);
        BSON_APPEND_UTF8(res_doc, "time", format_time);
        BSON_APPEND_UTF8(res_doc, "level", output_level_to_string(item->level));
        BSON_APPEND_UTF8(res_doc, "ip_proto",
                         ip_proto_to_string(item->target.ip_proto));
        ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->target.ip_them);
        ipaddress_formatted_t ip_me_fmt   = ipaddress_fmt(item->target.ip_me);
        BSON_APPEND_UTF8(res_doc, "ip_them", ip_them_fmt.string);
        BSON_APPEND_UTF8(res_doc, "ip_me", ip_me_fmt.string);
    }

    if (!item->no_port) {
        BSON_APPEND_INT32(res_doc, "port_them", item->target.port_them);
        BSON_APPEND_INT32(res_doc, "port_me", item->target.port_me);
    }

    DataLink *pre = item->report.link;
    while (pre->next) {
        if (pre->next->link_type == LinkType_String) {
            BSON_APPEND_UTF8(res_doc, pre->next->name,
                             (char *)pre->next->value_data);
        } else if (pre->next->link_type == LinkType_Int) {
            BSON_APPEND_INT64(res_doc, pre->next->name, pre->next->value_int);
        } else if (pre->next->link_type == LinkType_Double) {
            BSON_APPEND_DOUBLE(res_doc, pre->next->name,
                               pre->next->value_double);
        } else if (pre->next->link_type == LinkType_Bool) {
            BSON_APPEND_BOOL(res_doc, pre->next->name, pre->next->value_bool);
        } else if (pre->next->link_type == LinkType_Binary) {
            BSON_APPEND_BINARY(res_doc, pre->next->name, BSON_SUBTYPE_BINARY,
                               pre->next->value_data, pre->next->data_len);
        }

        pre = pre->next;
    }

    fwrite(bson_get_data(res_doc), 1, res_doc->len, file);
    bson_destroy(res_doc);

    return;
}

static void bsonout_close(const OutConf *out) {
    fflush(file);
    if (file != stdout) {
        fclose(file);
    }
}

Output BsonOutput = {
    .name       = "bson",
    .need_file  = true,
    .params     = bson_parameters,
    .short_desc = "Save results in BSON(Binary JSON) format.",
    .desc =
        "BsonOutput save results in BSON(Binary JSON) format to "
        "specified file. BSON is a binary-encoded serialization format used to "
        "store and exchange data in a compact and efficient way. It is similar "
        "to JSON but stores data in a binary format, making it more efficient "
        "for data storage and transmission.\n"
        "NOTE1: BsonOutput saves all results as a series of BSON documents to "
        "file.\n "
        "NOTE2: BsonOutput could save complete binary type fields in results.\n"
        "NOTE3: " XTATE_NAME_TITLE_CASE
        " could decode BSON result file to JSON format with `--parse-bson` "
        "parameter. Or we can use bsondump tool to decode it.\n"
        "Dependencies: libbson.",

    .init_cb   = &bsonout_init,
    .result_cb = &bsonout_result,
    .close_cb  = &bsonout_close,
};

/**
 * @return is printed successful.
 */
static bool print_bson_as_json(const uint8_t *bson_data, size_t bson_size) {
    char  *json_str;
    bson_t bson_doc;
    bool   is_success = true;

    if (!bson_init_static(&bson_doc, bson_data, bson_size)) {
        LOG(LEVEL_ERROR, "ParseBson: Failed to initialize BSON document.\n");
        is_success = false;
        goto bson_to_json_err1;
    }

    json_str = bson_as_json(&bson_doc, NULL);

    if (json_str) {
        printf("%s\n", json_str);
        bson_free(json_str);
    } else {
        LOG(LEVEL_ERROR, "ParseBson: Failed to convert BSON to JSON.\n");
        is_success = false;
    }

    bson_destroy(&bson_doc);

bson_to_json_err1:
    return is_success;
}

void parse_bson_file(const char *filename) {

    FILE *bsonfile = fopen(filename, "rb");
    if (bsonfile == NULL) {
        LOG(LEVEL_ERROR, "ParseBson: could not open BSON file %s.\n", filename);
        perror(filename);
        return;
    }

    while (true) {
        /*read the first 4 bytes as length of a BSON doc*/
        uint32_t doc_length = 0;
        size_t   read_size  = fread(&doc_length, 1, 4, bsonfile);
        if (read_size == 0) {
            /*EOF*/
            break;
        } else if (read_size < 4) {
            LOG(LEVEL_ERROR,
                "ParseBson: Incomplete length field. Corrupted file?\n");
            break;
        }

        /*get real doc len*/
        doc_length = BSON_UINT32_FROM_LE(doc_length);

        /*the shortest doc len*/
        if (doc_length < 5) {
            LOG(LEVEL_ERROR, "ParseBson: Invalid BSON document length: %u\n",
                doc_length);
            break;
        }

        // read remaining doc data
        size_t   remaining = doc_length - 4;
        uint8_t *bson_data = MALLOC(doc_length);

        // contains the len field
        ((uint32_t *)bson_data)[0] = BSON_UINT32_TO_LE(doc_length);

        read_size = fread(bson_data + 4, 1, remaining, bsonfile);
        if (read_size < remaining) {
            LOG(LEVEL_ERROR,
                "ParseBson: Incomplete BSON document. Expected %zu bytes, got "
                "%zu bytes.\n",
                remaining, read_size);
            FREE(bson_data);
            break;
        }

        // print BSON as JSON
        print_bson_as_json(bson_data, doc_length);

        FREE(bson_data);
    }

    fclose(bsonfile);
}

#endif
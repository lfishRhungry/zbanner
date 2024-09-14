#ifndef NOT_FOUND_BSON

#include "output-modules.h"

#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../pixie/pixie-file.h"

#include <bson/bson.h>

extern Output BsonOutput; /*for internal x-ref*/

static FILE *file;

// static char format_time[32];

static bool bsonout_init(const OutConf *out) {
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

    bool output_port = (item->target.ip_proto == IP_PROTO_TCP ||
                        item->target.ip_proto == IP_PROTO_UDP ||
                        item->target.ip_proto == IP_PROTO_SCTP);

    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->target.ip_them);
    ipaddress_formatted_t ip_me_fmt   = ipaddress_fmt(item->target.ip_me);

    // iso8601_time_str(format_time, sizeof(format_time), &item->timestamp);

    BSON_APPEND_DATE_TIME(res_doc, "time", (uint64_t)item->timestamp * 1000);
    // BSON_APPEND_UTF8(res_doc, "time", format_time);
    BSON_APPEND_UTF8(res_doc, "level", output_level_to_string(item->level));
    BSON_APPEND_UTF8(res_doc, "ip_proto",
                     ip_proto_to_string(item->target.ip_proto));
    BSON_APPEND_UTF8(res_doc, "ip_them", ip_them_fmt.string);
    BSON_APPEND_UTF8(res_doc, "ip_me", ip_me_fmt.string);

    if (output_port) {
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
    .name      = "bson",
    .need_file = 1,
    .params    = NULL,
    .desc =
        "BsonOutput save results in BSON(binary BSON) format to "
        "specified file. BSON is a binary-encoded serialization format used to "
        "store and exchange data in a compact and efficient way. It is similar "
        "to JSON but stores data in a binary format, making it more efficient "
        "for data storage and transmission.\n"
        "NOTE1: BsonOutput saves every results as a BSON document to file.\n "
        "NOTE2: BsonOutput could save binary type of fields in results.",

    .init_cb   = &bsonout_init,
    .result_cb = &bsonout_result,
    .close_cb  = &bsonout_close,
};

#endif
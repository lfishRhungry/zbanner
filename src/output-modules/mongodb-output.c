#ifndef NOT_FOUND_MONGOC

#include "output-modules.h"
#include "../version.h"
#include "../globals.h"

#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../pixie/pixie-file.h"

#include <mongoc/mongoc.h>

extern Output MongodbOutput; /*for internal x-ref*/

static char format_time[32];

struct MongodbConf {
    char                *db_name;
    char                *col_name;
    char                *app_name;
    mongoc_uri_t        *uri;
    mongoc_client_t     *client;
    mongoc_database_t   *database;
    mongoc_collection_t *collection;
    unsigned             is_compact : 1;
};

static struct MongodbConf mongodb_conf = {0};

static ConfRes SET_app_name(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    mongodb_conf.app_name = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_col_name(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    mongodb_conf.col_name = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_db_name(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    mongodb_conf.db_name = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_compact(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    mongodb_conf.is_compact = parse_str_bool(value);

    return Conf_OK;
}

static ConfParam mongodb_parameters[] = {
    {"database-name",
     SET_db_name,
     Type_ARG,
     {"db-name", "database", "db", 0},
     "Specifies the database name to use. Default is " XTATE_NAME "."},
    {"collection-name",
     SET_col_name,
     Type_ARG,
     {"col-name", "collection", "col", 0},
     "Specifies the collection name to store. Default is a timestamp of scan "
     "beginning."},
    {"application-name",
     SET_app_name,
     Type_ARG,
     {"app-name", "application", "app", 0},
     "Specifies the application name to register for tracking in the profile "
     "logs in MongoDB. Default is " XTATE_NAME " with version."},
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

static bool mongodbout_init(const XConf *xconf, const OutConf *out) {

    char         tm_buf[80];
    bool         retval;
    bson_error_t error;
    bson_t      *test_ping;
    bson_t      *test_insert;
    bson_t      *test_remove;
    bson_t       reply;
    bson_oid_t   oid;
    const char  *db_name;
    const char  *col_name;
    const char  *app_name;

    /*
     * Required to initialize libmongoc's internals
     */
    mongoc_init();

    /*
     * Safely create a MongoDB URI object from the given string
     */
    mongodb_conf.uri = mongoc_uri_new_with_error(out->output_filename, &error);
    if (!mongodb_conf.uri) {
        LOG(LEVEL_ERROR, "(MongodbOut) failed to parse URI[%s]: %s\n",
            out->output_filename, error.message);
        return false;
    }

    /*
     * Create a new client instance
     */
    mongodb_conf.client = mongoc_client_new_from_uri(mongodb_conf.uri);
    if (!mongodb_conf.client) {
        LOG(LEVEL_ERROR,
            "(MongodbOut) failed to create a new client instance.\n");
        return false;
    }

    /*
     * Register the application name so we can track it in the profile logs
     * on the server. This can also be done from the URI.
     */
    if (mongodb_conf.app_name && mongodb_conf.app_name[0]) {
        app_name = mongodb_conf.app_name;
    } else {
        app_name = XTATE_WITH_VERSION;
    }
    if (!mongoc_client_set_appname(mongodb_conf.client, app_name)) {
        LOG(LEVEL_ERROR, "(MongodbOut) failed to set appname: %s\n", app_name);
        return false;
    }

    /*
     * Get a handle on the database "db_name" and collection "coll_name"
     */
    if (mongodb_conf.db_name && mongodb_conf.db_name[0]) {
        db_name = mongodb_conf.db_name;
    } else {
        db_name = XTATE_NAME;
    }
    mongodb_conf.database =
        mongoc_client_get_database(mongodb_conf.client, db_name);
    if (mongodb_conf.col_name && mongodb_conf.col_name[0]) {
        col_name = mongodb_conf.col_name;
    } else {
        struct tm *timeinfo;
        timeinfo = localtime(&global_now);
        strftime(tm_buf, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
        col_name = tm_buf;
    }
    mongodb_conf.collection =
        mongoc_client_get_collection(mongodb_conf.client, db_name, col_name);

    /*
     * Test server alive by pinging the database
     */
    test_ping = BCON_NEW("ping", BCON_INT32(1));
    retval    = mongoc_client_command_simple(mongodb_conf.client, "admin",
                                             test_ping, NULL, &reply, &error);
    if (!retval) {
        LOG(LEVEL_ERROR, "(MongodbOut ping test) %s(%u)\n", error.message,
            error.code);
        return false;
    }
    bson_destroy(&reply);

    /*
     * Test data inserting
     */
    bson_oid_init(&oid, NULL);
    test_insert = bson_new();
    BSON_APPEND_UTF8(test_insert, "hello", XTATE_NAME);
    BSON_APPEND_OID(test_insert, "_id", &oid);
    if (!mongoc_collection_insert_one(mongodb_conf.collection, test_insert,
                                      NULL, NULL, &error)) {
        LOG(LEVEL_ERROR, "(MongodbOut insert test) %s(%u)\n", error.message,
            error.code);
        return false;
    }

    /*
     * Test data removing by the way
     */
    test_remove = bson_new();
    BSON_APPEND_OID(test_remove, "_id", &oid);
    if (!mongoc_collection_delete_one(mongodb_conf.collection, test_remove,
                                      NULL, &reply, &error)) {
        LOG(LEVEL_ERROR, "(MongodbOut remove test) %s(%u)\n", error.message,
            error.code);
        return false;
    }

    bson_destroy(test_ping);
    bson_destroy(test_insert);
    bson_destroy(test_remove);
    bson_destroy(&reply);

    return true;
}

static void mongodbout_result(OutItem *item) {
    bson_error_t error;
    bson_t      *res_doc = bson_new();

    /**
     * Add _id at first.
     * Or let MongoDB add it automatically.
     * */
    // bson_oid_t   oid;
    // bson_oid_init(&oid, NULL);
    // BSON_APPEND_OID(res_doc, "_id", &oid);

    if (mongodb_conf.is_compact) {
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

    /*Insert the documantation*/
    if (!mongoc_collection_insert_one(mongodb_conf.collection, res_doc, NULL,
                                      NULL, &error)) {
        LOG(LEVEL_ERROR, "(MongodbOut insert) %s: %u\n", error.message,
            error.code);
    }

    bson_destroy(res_doc);

    return;
}

static void mongodbout_close(const OutConf *out) {
    if (mongodb_conf.collection) {
        mongoc_collection_destroy(mongodb_conf.collection);
        mongodb_conf.collection = NULL;
    }
    if (mongodb_conf.database) {
        mongoc_database_destroy(mongodb_conf.database);
        mongodb_conf.database = NULL;
    }
    if (mongodb_conf.uri) {
        mongoc_uri_destroy(mongodb_conf.uri);
        mongodb_conf.uri = NULL;
    }
    if (mongodb_conf.client) {
        mongoc_client_destroy(mongodb_conf.client);
        mongodb_conf.client = NULL;
    }
    mongoc_cleanup();
}

Output MongodbOutput = {
    .name       = "mongodb",
    .need_file  = true,
    .params     = mongodb_parameters,
    .short_desc = "Save results to MongoDB.",
    .desc = "MongodbOutput save results in MongoDB. MongoDB is a popular, "
            "open-source NoSQL database that uses a document-oriented data "
            "model. It is known for its high performance, high availability, "
            "and easy scalability. MongoDB stores data in flexible, BSON "
            "documents(JSON-like), which makes it easy and suitable to store "
            "results from " XTATE_NAME_TITLE_CASE "."
            "NOTE1: MongodbOutput saves all results as a series of BSON "
            "documents to MongoDB.\n"
            "NOTE2: MongodbOutput could save complete binary type fields in "
            "results.\n"
            "NOTE3: " XTATE_NAME_TITLE_CASE
            " could decode result file from BsonOutput to MongoDB with "
            "`--store-bson` parameter.\n"
            "Dependencies: libmongoc.",

    .init_cb   = &mongodbout_init,
    .result_cb = &mongodbout_result,
    .close_cb  = &mongodbout_close,
};

#endif
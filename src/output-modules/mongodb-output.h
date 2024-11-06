
#ifndef NOT_FOUND_MONGOC
#ifndef MONGODB_OUTPUT_H
#define MONGODB_OUTPUT_H

/**
 * store results from BSON file to MongoDB.
 */
void store_bson_file(const char *filename, const char *uri_name,
                     const char *db_name, const char *col_name,
                     const char *app_name);

#endif
#endif
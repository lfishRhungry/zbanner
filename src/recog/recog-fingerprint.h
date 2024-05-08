#ifndef RECOG_FINGERPRINT_H
#define RECOG_FINGERPRINT_H

#include <stddef.h>

#include "../util-misc/cross.h"

struct Recog_FP;

/**
 * load fingerprints in Recog format from xml file
 * @param filename xml filename/path
 * @param unprefix unprefix the `^` from the head of regex
 * @param unsuffix unsuffix the `$` from the tail of regex
*/
struct Recog_FP * load_recog_fp(const char *filename, bool unprefix, bool unsuffix);

const char *
match_recog_fp(struct Recog_FP *fp,
    const unsigned char *payload, size_t payload_len);

void free_recog_fp(struct Recog_FP *fp);

#endif
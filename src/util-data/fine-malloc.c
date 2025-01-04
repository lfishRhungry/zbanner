#include "fine-malloc.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "../util-out/logger.h"

#define MAXNUM ((size_t)1 << (sizeof(size_t) * 4))

/***************************************************************************
 ***************************************************************************/
void *REALLOCARRAY(void *p, size_t count, size_t size) {
    if (count >= MAXNUM || size >= MAXNUM) {
        if (size != 0 && count >= SIZE_MAX / size) {
            LOG(LEVEL_ERROR, "alloc too large, aborting\n");
            abort();
        }
    }

    void *ret = realloc(p, count * size);
    if (ret == NULL && count * size != 0) {
        LOG(LEVEL_ERROR, "out of memory, aborting\n");
        abort();
    }

    return ret;
}

/***************************************************************************
 ***************************************************************************/
void *CALLOC(size_t count, size_t size) {
    void *p;

    if (count >= MAXNUM || size >= MAXNUM) {
        if (size != 0 && count >= SIZE_MAX / size) {
            LOG(LEVEL_ERROR, "alloc too large, aborting\n");
            abort();
        }
    }

    p = calloc(count, size);
    if (p == NULL && count * size != 0) {
        LOG(LEVEL_ERROR, "out of memory, aborting\n");
        abort();
    }

    return p;
}

/***************************************************************************
 * Wrap the standard 'malloc()' function.
 * - never returns a NULL pointer, aborts program instead
 * - if size is zero, still returns a valid pointer to one byte
 ***************************************************************************/
void *MALLOC(size_t size) {
    void *p;

    /* If 'size' is zero, then the behavior of 'malloc()' is undefined.
     * I'm not sure which behavior would be best, to either always abort
     * or always succeed. I'm choosing "always succeed" by bumping the
     * length by one byte */
    if (size == 0)
        size = 1;

    /* Do the original allocation */
    p = malloc(size);

    /* Abort the program if we've run out of memory */
    if (p == NULL) {
        LOG(LEVEL_ERROR, "out of memory, aborting\n");
        abort();
    }

    /* At this point, we've either succeeded or aborted the program,
     * so this value is guaranteed to never be NULL */
    return p;
}

/***************************************************************************
 ***************************************************************************/
void *REALLOC(void *p, size_t size) {
    void *ret = realloc(p, size);

    if (ret == NULL) {
        LOG(LEVEL_ERROR, "out of memory, aborting\n");
        abort();
    }

    return ret;
}

/***************************************************************************
 ***************************************************************************/
char *STRDUP(const char *str) {
#if defined(_WIN32)
    char *p = _strdup(str);
#else
    char *p = strdup(str);
#endif

    if (p == NULL && str != NULL) {
        LOG(LEVEL_ERROR, "out of memory, aborting\n");
        abort();
    }

    return p;
}

/*****************************************************************************
 * strdup(): compilers don't like strdup(), so I just write my own here. I
 * should probably find a better solution.
 *****************************************************************************/
char *DUP_STR(const char *str) {
    size_t length;
    char  *result;

    /* Find the length of the string. We allow NULL strings, in which case
     * the length is zero */
    if (str == NULL)
        length = 0;
    else
        length = strlen(str);

    /* Allocate memory for the string */
    result = MALLOC(length + 1);

    /* Copy the string */
    if (str)
        memcpy(result, str, length + 1);
    result[length] = '\0';

    return result;
}
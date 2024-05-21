/*
    Data Chain

    This module remembers a series of "data" identified by "name".
    These are often simple strings, like the FTP hello string.
    I provide funcs to append data/string conveniently.

    I try to maintain c string in data by keeping '\0' tail.
    But you can break this by appending special string.

    For out-of-box using and simple iterating, structures are exposed.
    Change internal contents of structures after understanding code.
    C is dangerous and charming, right?

    Datachain was inspired by banout of masscan but with different
    target, usage and internal code.

    Create by lishRhungry 2024
*/
#include "data-chain.h"
#include "fine-malloc.h"
#include "safe-string.h"
#include "../util-out/logger.h"

#include <stddef.h>
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>



static unsigned
_name_hash(const char *name) {
    unsigned hash  = 0;
    unsigned prime = 151;
    while (*name) {
        hash = hash * prime + (*name++);
    }
    return hash;
}

/**
 * Create a data link by yourself and put it after the dummy node.
 * The actual size of data won't be less than DACH_DEFAULT_DATA_SIZE.
 * NOTE: the name must not exist
 */
static void
_dach_new_link(struct DataChain *dach, const char *name, size_t len, bool is_number)
{
    /*keep a space for '\0'*/
    size_t data_size   = len<DACH_DEFAULT_DATA_SIZE?DACH_DEFAULT_DATA_SIZE:len+1;
    struct DataLink *p = CALLOC(1, sizeof(struct DataLink) + data_size);

    safe_strcpy(p->name, DACH_MAX_NAME_SIZE, name);

    p->name_hash       = _name_hash(name);
    p->data_size       = data_size;
    p->next            = dach->link->next;
    p->is_number       = is_number;
    dach->link->next   = p;

    dach->count++;
}

struct DataLink *
dach_new_link(struct DataChain *dach, const char *name, size_t data_size, bool is_number)
{
    struct DataLink *pre = dach_find_pre_link(dach, name);

    if (pre->next == NULL) {
        _dach_new_link(dach, name, data_size, is_number);
        pre = dach->link;
    }

    return pre;
}

/**
 * Create a data link with formatted name and specified capacity by yourself.
 * NOTE: return old pre if the link exists
 * @return the pre of new link
 */
static struct DataLink *
_dach_new_link_vprintf(struct DataChain *dach, size_t data_size,
    bool is_number, const char *fmt_name, va_list marker)
{
    char str[DACH_MAX_NAME_SIZE];
    int  len;

    /*may be `name` has no enough size, but it must be c string!*/
    len = vsnprintf(str, sizeof(str), fmt_name, marker);
    if (len > sizeof(str)-1) {
        str[sizeof(str)-1] = '\0';
    }

    /*ensure not exist*/
    struct DataLink *pre = dach_find_pre_link(dach, str);

    if (pre->next == NULL) {
        _dach_new_link(dach, str, data_size, is_number);
        pre = dach->link;
    }

    return pre;
}

struct DataLink *
dach_new_link_printf(struct DataChain *dach, size_t data_size,
    bool is_number, const char *fmt_name, ...)
{
    struct DataLink *pre;
    va_list marker;

    va_start(marker, fmt_name);
    pre = _dach_new_link_vprintf(dach, data_size, is_number, fmt_name, marker);
    va_end(marker);

    return pre;
}


/**
 * Expand the target link size to at least mlen by inputting its previous link.
 * NOTE: pre & pre->next must not be NULL
 */
static void
_dach_link_expand(struct DataLink *pre, size_t mlen)
{
    assert(pre && pre->next);

    struct DataLink *n;
    size_t length;

    /*keep a space for '\0'*/
    length = mlen<(2*pre->next->data_size)?(2*pre->next->data_size):mlen+1;
    n      = CALLOC(1, sizeof(struct DataLink) + length);

    memcpy(n, pre->next, offsetof(struct DataLink, data) + pre->next->data_size);
    n->data_size = length;

    free(pre->next);
    pre->next = n;
}


/***************************************************************************
 ***************************************************************************/
void
dach_release(struct DataChain *dach)
{
    struct DataLink *link = dach->link;

    /*release all except dummy node*/
    while (link->next) {
        struct DataLink *next = link->next->next;
        free(link->next);
        link->next = next;
    }

    link->next = NULL;
}

/***************************************************************************
 ***************************************************************************/
struct DataLink *
dach_find_pre_link(struct DataChain *dach, const char *name)
{
    unsigned hash = _name_hash(name);

    struct DataLink *pre = dach->link;
    while (pre->next && pre->next->name_hash != hash)
        pre = pre->next;

    return pre;
}

struct DataLink *
dach_find_link(struct DataChain *dach, const char *name)
{
    return dach_find_pre_link(dach, name)->next;
}

/***************************************************************************
 ***************************************************************************/
struct DataLink *
dach_get_pre_link(struct DataChain *dach, const char *name)
{
    struct DataLink *pre = dach_find_pre_link(dach, name);

    if (pre->next == NULL) {
        _dach_new_link(dach, name, 1, false);
        pre = dach->link;
    }

    return pre;
}

struct DataLink *
dach_get_link(struct DataChain *dach, const char *name)
{
    return dach_get_pre_link(dach, name)->next;
}

/*
 * Try to maintain a c string by keeping at least a '\0' in tails of data
 * ref:
 *     new_link
 *     expand
*/

void
dach_del_link_by_pre(struct DataChain *dach, struct DataLink *pre)
{
    assert(pre);

    if (pre->next) {
        struct DataLink *link = pre->next;
        pre->next = link->next;
        free(link);
        dach->count--;
    }
}

void
dach_del_link(struct DataChain *dach, const char *name)
{
    struct DataLink *pre = dach_find_pre_link(dach, name);
    dach_del_link_by_pre(dach, pre);
}


/***************************************************************************
 ***************************************************************************/
void
dach_append_by_pre(struct DataLink *pre, 
    const void *px, size_t length)
{
    assert(pre && pre->next);

    if (length == DACH_AUTO_LEN)
        length = strlen((const char*)px);

    size_t min_len = pre->next->data_len + length;
    if (min_len >= pre->next->data_size) { /*at least keep a '\0'*/
        _dach_link_expand(pre, min_len);
    }

    memcpy(pre->next->data + pre->next->data_len, px, length);
    pre->next->data_len = min_len;
}

/***************************************************************************
 ***************************************************************************/
struct DataLink *
dach_append(struct DataChain *dach, const char *name, 
    const void *px, size_t length)
{
    struct DataLink *pre = dach_find_pre_link(dach, name);

    if (pre->next == NULL) {
        _dach_new_link(dach, name, length, false);
        pre = dach->link;
    }

    dach_append_by_pre(pre, px, length);

    return pre;
}

/***************************************************************************
 ***************************************************************************/
void
dach_append_char_by_pre(struct DataLink *pre, int c)
{
    char cc = (char)c;
    dach_append_by_pre(pre, &cc, 1);
}

/***************************************************************************
 ***************************************************************************/
struct DataLink *
dach_append_char(struct DataChain *dach, const char *name, int c)
{
    struct DataLink *pre = dach_find_pre_link(dach, name);

    if (pre->next == NULL) {
        _dach_new_link(dach, name, 1, false);
        pre = dach->link;
    }

    dach_append_char_by_pre(pre, c);

    return pre;
}

/***************************************************************************
 ***************************************************************************/
void
dach_append_hexint_by_pre(struct DataLink *pre,
    unsigned long long number, int digits)
{
    if (digits == 0) {
        for (digits=16; digits>0; digits--)
            if (number>>((digits-1)*4) & 0xF)
                break;
    }


    for (;digits>0; digits--) {
        char c = "0123456789abcdef"[(number>>(unsigned long long)((digits-1)*4)) & 0xF];
        dach_append_char_by_pre(pre, c);
    }
}

/***************************************************************************
 ***************************************************************************/
struct DataLink *
dach_append_hexint(struct DataChain *dach, const char *name,
    unsigned long long number, int digits)
{
    struct DataLink *pre = dach_find_pre_link(dach, name);

    if (pre->next == NULL) {
        _dach_new_link(dach, name, 1, false); /*use default*/
        pre = dach->link;
    }

    if (digits == 0) {
        for (digits=16; digits>0; digits--)
            if (number>>((digits-1)*4) & 0xF)
                break;
    }

    for (;digits>0; digits--) {
        char c = "0123456789abcdef"[(number>>(unsigned long long)((digits-1)*4)) & 0xF];
        dach_append_char_by_pre(pre, c);
    }

    return pre;
}

/***************************************************************************
 ***************************************************************************/
void
dach_append_unicode_by_pre(struct DataLink *pre, unsigned c)
{
    if (c & ~0xFFFF) {
        unsigned c2;
        c2 = 0xF0 | ((c>>18)&0x03);
        dach_append_char_by_pre(pre, c2);
        c2 = 0x80 | ((c>>12)&0x3F);
        dach_append_char_by_pre(pre, c2);
        c2 = 0x80 | ((c>> 6)&0x3F);
        dach_append_char_by_pre(pre, c2);
        c2 = 0x80 | ((c>> 0)&0x3F);
        dach_append_char_by_pre(pre, c2);
    } else if (c & ~0x7FF) {
        unsigned c2;
        c2 = 0xE0 | ((c>>12)&0x0F);
        dach_append_char_by_pre(pre, c2);
        c2 = 0x80 | ((c>> 6)&0x3F);
        dach_append_char_by_pre(pre, c2);
        c2 = 0x80 | ((c>> 0)&0x3F);
        dach_append_char_by_pre(pre, c2);
    } else if (c & ~0x7f) {
        unsigned c2;
        c2 = 0xc0 | ((c>> 6)&0x1F);
        dach_append_char_by_pre(pre, c2);
        c2 = 0x80 | ((c>> 0)&0x3F);
        dach_append_char_by_pre(pre, c2);
    } else
        dach_append_char_by_pre(pre, c);
}

/***************************************************************************
 ***************************************************************************/
struct DataLink *
dach_append_unicode(struct DataChain *dach, const char *name, unsigned c)
{
    struct DataLink *pre = dach_find_pre_link(dach, name);

    if (pre->next == NULL) {
        _dach_new_link(dach, name, 1, false); /*use default*/
        pre = dach->link;
    }

    dach_append_unicode_by_pre(pre, c);

    return pre;
}


/***************************************************************************
 * NOTE: pre & pre->next must not be NULL
 ***************************************************************************/
static void
_dach_vprintf(struct DataLink *pre, const char *fmt, va_list marker) {

    char str[50];
    int  len;

    len = vsnprintf(str, sizeof(str), fmt, marker);
    if (len > sizeof(str)-1) {
        char *tmp = MALLOC(len+1);
        vsnprintf(tmp, len+1, fmt, marker);
        dach_append_by_pre(pre, tmp, len);
        free(tmp);
    } else {
        dach_append_by_pre(pre, str, len);
    }
}

/***************************************************************************
 ***************************************************************************/
void
dach_printf_by_pre(struct DataLink *pre, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    _dach_vprintf(pre, fmt, marker);
    va_end(marker);
}

/***************************************************************************
 ***************************************************************************/
struct DataLink *
dach_printf(struct DataChain *dach, const char *name, bool is_number, const char *fmt, ...)
{
    struct DataLink *pre = dach_find_pre_link(dach, name);

    if (pre->next == NULL) {
        /*we don't know the exact length, use default*/
        _dach_new_link(dach, name, 1, is_number);
        pre = dach->link;
    }

    va_list marker;

    va_start(marker, fmt);
    _dach_vprintf(pre, fmt, marker);
    va_end(marker);

    return pre;
}

/***************************************************************************
 ***************************************************************************/
void dach_append_normalized_by_pre(struct DataLink *pre,
    const void *px, size_t length)
{
    if (length == DACH_AUTO_LEN)
        length = strlen((const char*)px);

    for (size_t i=0; i<length; i++) {
        int c = ((const char*)px)[i];
        if (isprint(c) && c != '<' && c != '>' && c != '&' && c != '\\' && c != '\"' && c != '\'') {
            dach_append_char_by_pre(pre, c);
        } else {
            dach_append_by_pre(pre, "\\x", 2);
            dach_append_char_by_pre(pre, "0123456789abcdef"[c>>4]);
            dach_append_char_by_pre(pre, "0123456789abcdef"[c&0xF]);
        }
    }
}

/***************************************************************************
 ***************************************************************************/
struct DataLink *
dach_append_normalized(struct DataChain *dach, const char *name,
    const void *px, size_t length)
{
    if (length == DACH_AUTO_LEN)
        length = strlen((const char*)px);

    struct DataLink *pre = dach_find_pre_link(dach, name);

    if (pre->next == NULL) {
        _dach_new_link(dach, name,
            length<DACH_DEFAULT_DATA_SIZE?length*4:length*2,
            false); /*estimate the encoded length*/
        pre = dach->link;
    }

    dach_append_normalized_by_pre(pre, px, length);

    return pre;
}

/***************************************************************************
 ***************************************************************************/
bool
dach_link_contains(struct DataLink *link, const char *string)
{
    assert(link && link->data);

    if (string==NULL) return false;

    const unsigned char *string2 = link->next->data;
    size_t string2_length        = link->data_len;
    size_t string_length         = strlen(string);

    if (string_length > string2_length)
        return false;
    
    for (size_t i=0; i<string2_length-string_length+1; i++) {
        if (memcmp(string, string2+i, string_length) == 0)
            return true;
    }

    return false;
}

/***************************************************************************
 ***************************************************************************/
bool
dach_contains(struct DataChain *dach, const char *name,
    const char *string)
{
    if (string==NULL) return false;

    struct DataLink *link = dach_find_link(dach, name);
    if (link==NULL) return false;

    return dach_link_contains(link, string);
}


/*****************************************************************************
 *****************************************************************************/
bool
dach_link_equals(struct DataLink *link, const char *rhs)
{
    assert(link && link->data);

    const unsigned char *lhs = link->data;

    size_t lhs_length = link->data_len;
    size_t rhs_length = strlen(rhs);
    
    if (lhs_length != rhs_length)
        return false;

    return memcmp(lhs, rhs, rhs_length) == 0;
}


/*****************************************************************************
 *****************************************************************************/
bool
dach_equals(struct DataChain *dach, const char *name, const char *rhs)
{
    struct DataLink *link = dach_find_link(dach, name);
    if (link==NULL) return false;

    return dach_link_equals(link, rhs);
}

/*****************************************************************************
 *****************************************************************************/
static const char *b64 =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789"
"+/";


/*****************************************************************************
 *****************************************************************************/
void
dach_init_base64(struct DataChainB64 *base64)
{
    base64->state = 0;
    base64->temp  = 0;
}

/*****************************************************************************
 *****************************************************************************/
void
dach_append_base64_by_pre(struct DataLink *pre,
    const void *vpx, size_t length, struct DataChainB64 *base64)
{
    if (length == DACH_AUTO_LEN)
        length = strlen((const char*)vpx);

    const unsigned char *px = (const unsigned char *)vpx;
    size_t i;
    unsigned x = base64->temp;
    unsigned state = base64->state;
    
    for (i=0; i<length; i++) {
        switch (state) {
            case 0:
                x = px[i]<<16;
                state++;
                break;
            case 1:
                x |= px[i]<<8;
                state++;
                break;
            case 2:
                x |= px[i];
                state = 0;
                dach_append_char_by_pre(pre, b64[(x>>18)&0x3F]);
                dach_append_char_by_pre(pre, b64[(x>>12)&0x3F]);
                dach_append_char_by_pre(pre, b64[(x>> 6)&0x3F]);
                dach_append_char_by_pre(pre, b64[(x>> 0)&0x3F]);
        }
    }
    
    base64->temp = x;
    base64->state = state;
}

/*****************************************************************************
 *****************************************************************************/
struct DataLink *
dach_append_base64(struct DataChain *dach, const char *name,
    const void *vpx, size_t length, struct DataChainB64 *base64)
{
    struct DataLink *pre = dach_find_pre_link(dach, name);

    if (pre->next == NULL) {
        if (length == DACH_AUTO_LEN)
            length = strlen((const char*)vpx);
        /*len after encoding*/
        _dach_new_link(dach, name, ((length+2)/3)*4, false);
        pre = dach->link;
    }

    dach_append_base64_by_pre(pre, vpx, length, base64);

    return pre;
}

/*****************************************************************************
 *****************************************************************************/
void
dach_finalize_base64_by_pre(struct DataLink *pre, struct DataChainB64 *base64)
{
    unsigned x = base64->temp;
    switch (base64->state) {
        case 0:
            break;
        case 1:
            dach_append_char_by_pre(pre, b64[(x>>18)&0x3F]);
            dach_append_char_by_pre(pre, b64[(x>>12)&0x3F]);
            dach_append_by_pre(pre, "==", 2);
            break;
        case 2:
            dach_append_char_by_pre(pre, b64[(x>>18)&0x3F]);
            dach_append_char_by_pre(pre, b64[(x>>12)&0x3F]);
            dach_append_char_by_pre(pre, b64[(x>>6)&0x3F]);
            dach_append_char_by_pre(pre, '=');
            break;
    }
}

/*****************************************************************************
 *****************************************************************************/
void
dach_finalize_base64(struct DataChain *dach, const char *name,
    struct DataChainB64 *base64)
{
    struct DataLink *pre = dach_find_pre_link(dach, name);

    if (pre->next == NULL) return;

    dach_finalize_base64_by_pre(pre, base64);
}

/*****************************************************************************
 *****************************************************************************/
int
datachain_selftest(void)
{
    unsigned line = 0;

    /*
     * Basic test
     */
    {
        struct DataChain *dach = CALLOC(1, sizeof(struct DataChain));
        struct DataLink  *link;
        unsigned i;

        for (i=0; i<10; i++) {
            dach_append(dach, "x", "xxxx", 4);
            dach_append(dach, "y", "yyyyy", DACH_AUTO_LEN);
        }

        for (i=0; i<10; i++) {
            dach_append_char(dach, "x", 'x');
            dach_append_char(dach, "y", 'y');
        }

        if (dach->link->next == NULL) {
            line = __LINE__;
            goto fail;
        }

        if (dach->count!=2) {
            line = __LINE__;
            goto fail;
        }

        link = dach_find_link(dach, "x");
        if (link==NULL) {
            line = __LINE__;
            goto fail;
        }
        if (link->data_len != 50) {
            line = __LINE__;
            goto fail;
        }

        link = dach_find_link(dach, "y");
        if (link==NULL) {
            line = __LINE__;
            goto fail;
        }
        if (link->data_len != 60) {
            line = __LINE__;
            goto fail;
        }

        dach_del_link(dach, "x");

        link = dach_find_link(dach, "x");
        if (link) {
            line = __LINE__;
            goto fail;
        }

        if (dach->count!=1) {
            line = __LINE__;
            goto fail;
        }

        dach_append_normalized(dach, "normal", "<hello>\n", DACH_AUTO_LEN);
        link = dach_find_link(dach, "normal");
        if (link==NULL) {
            line = __LINE__;
            goto fail;
        }
        if (!dach_equals(dach, "normal", "\\x3chello\\x3e\\x0a")) {
            line = __LINE__;
            goto fail;
        }

        dach_printf(dach, "print", "%s is %d", "65", 65);
        link = dach_find_link(dach, "print");
        if (link==NULL) {
            line = __LINE__;
            goto fail;
        }
        if (!dach_equals(dach, "print", "65 is 65")) {
            line = __LINE__;
            goto fail;
        }

        if (dach->count!=3) {
            line = __LINE__;
            goto fail;
        }

        dach_del_link(dach, "normal");
        link = dach_find_link(dach, "normal");
        if (link) {
            line = __LINE__;
            goto fail;
        }

        if (dach->count!=2) {
            line = __LINE__;
            goto fail;
        }


        dach_release(dach);
        if (dach->link->next != NULL) {
            line = __LINE__;
            goto fail;
        }
        
        free(dach);
    }
    
    /*
     * Test BASE64 encoding. We are going to do strings of various lengths
     * in order to test the boundary condition of finalizing various strings
     * properly
     */
    {
        struct DataChain *dach = CALLOC(1, sizeof(struct DataChain));
        struct DataChainB64 base64[1];

        dach_init_base64(base64);
        dach_append_base64(dach, "1", "x", 1, base64);
        dach_finalize_base64(dach, "1", base64);

        dach_init_base64(base64);
        dach_append_base64(dach, "2", "bc", 2, base64);
        dach_finalize_base64(dach, "2", base64);

        dach_init_base64(base64);
        dach_append_base64(dach, "3", "mno", 3, base64);
        dach_finalize_base64(dach, "3", base64);

        dach_init_base64(base64);
        dach_append_base64(dach, "4", "stuv", 4, base64);
        dach_finalize_base64(dach, "4", base64);

        dach_init_base64(base64);
        dach_append_base64(dach, "5", "fghij", 5, base64);
        dach_finalize_base64(dach, "5", base64);


        if (!dach_equals(dach, "1", "eA==")) {
            line = __LINE__;
            goto fail;
        }
        if (!dach_equals(dach, "2", "YmM=")) {
            line = __LINE__;
            goto fail;
        }
        if (!dach_equals(dach, "3", "bW5v")) {
            line = __LINE__;
            goto fail;
        }
        if (!dach_equals(dach, "4", "c3R1dg==")) {
            line = __LINE__;
            goto fail;
        }
        if (!dach_equals(dach, "5", "ZmdoaWo=")) {
            line = __LINE__;
            goto fail;
        }

        dach_release(dach);
        free(dach);
    }

    return 0;

fail:
    LOG(LEVEL_ERROR, "[-] selftest: 'datachain' failed, file=%s, line=%u\n", __FILE__, line);
    return 1;
}

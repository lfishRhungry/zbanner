/*
    Data Chain

    This module remembers a series of "name" & "data" identified by id.
    These are often simple strings, like the FTP hello string.

    From masscan's `banout`
    Modified by lishRhungry 2024
*/
#include "data-chain.h"
#include "fine-malloc.h"
#include "safe-string.h"

#include <stddef.h>
#include <stdarg.h>


static unsigned name_hash(const char *name) {
    unsigned hash  = 0;
    unsigned prime = 151;
    while (*name) {
        hash = hash * prime + (*name++);
    }
    return hash;
}


/***************************************************************************
 ***************************************************************************/
void
datachain_release(struct DataChain *dach)
{
    struct DataLink *link = dach->link;
    while (link->next) {
        struct DataLink *next = link->next->next;
        free(link->next);
        link->next = next;
    }

    free(link);

    dach->link = NULL;
}


/***************************************************************************
 ***************************************************************************/
static struct DataLink *
datachain_find_link(struct DataChain *dach, const char *name)
{
    unsigned hash = name_hash(name);

    struct DataLink *link = dach->link;
    while (link && link->name_hash != hash)
        link = link->next;
    return link;
}

/***************************************************************************
 ***************************************************************************/
const unsigned char *
datachain_string(const struct DataChain *dach, const char *name)
{
    struct DataLink *link = dach->link;
    unsigned hash = name_hash(name);

    while (link && link->name_hash != hash)
        link = link->next;

    if (link)
        return link->data;
    else
        return NULL;
}

/***************************************************************************
 ***************************************************************************/
unsigned
datachain_is_equal(const struct DataChain *dach, const char *name,
    const char *string)
{
    const unsigned char *string2;
    size_t string_length;
    size_t string2_length;

    /*
     * Grab the string
     */
    string2 = datachain_string(dach, name);
    if (string2 == NULL)
        return string == NULL;

    if (string == NULL)
        return 0;
    
    string_length = strlen(string);
    string2_length = datachain_string_length(dach, name);

    if (string_length != string2_length)
        return 0;
    
    return memcmp(string, string2, string2_length) == 0;
}

/***************************************************************************
 ***************************************************************************/
unsigned
datachain_is_contains(const struct DataChain *dach, const char *name,
    const char *string)
{
    const unsigned char *string2;
    size_t string_length;
    size_t string2_length;
    size_t i;

    /*
     * Grab the string
     */
    string2 = datachain_string(dach, name);
    if (string2 == NULL)
        return string == NULL;

    if (string == NULL)
        return 0;
    
    string_length = strlen(string);
    string2_length = datachain_string_length(dach, name);

    if (string_length > string2_length)
        return 0;
    
    for (i=0; i<string2_length-string_length+1; i++) {
        if (memcmp(string, string2+i, string_length) == 0)
            return 1;
    }
    return 0;
}

/***************************************************************************
 ***************************************************************************/
unsigned
datachain_string_length(const struct DataChain *dach, const char *name)
{
    struct DataLink *link = dach->link;
    unsigned hash = name_hash(name);

    while (link && link->name_hash != hash)
        link = link->next;

    if (link)
        return link->data_len;
    else
        return 0;
}

/***************************************************************************
 ***************************************************************************/
void
datachain_end(struct DataChain *dach, const char *name)
{
    struct DataLink *p;

    p = datachain_find_link(dach, name);
    if (p && p->data_len) {
        p->name_hash |= 0x80000000;
    }
}

/***************************************************************************
 ***************************************************************************/
void
datachain_append_char(struct DataChain *dach, const char *name, int c)
{
    char cc = (char)c;
    datachain_append(dach, name, &cc, 1);
}

/***************************************************************************
 ***************************************************************************/
void
datachain_append_hexint(struct DataChain *dach, const char *name,
    unsigned long long number, int digits)
{
    if (digits == 0) {
        for (digits=16; digits>0; digits--)
            if (number>>((digits-1)*4) & 0xF)
                break;
    }
    
    for (;digits>0; digits--) {
        char c = "0123456789abcdef"[(number>>(unsigned long long)((digits-1)*4)) & 0xF];
        datachain_append_char(dach, name, c);
    }
}

/***************************************************************************
 * Output either a normal character, or the hex form of a UTF-8 string
 ***************************************************************************/
void
datachain_append_unicode(struct DataChain *dach, const char *name, unsigned c)
{
    if (c & ~0xFFFF) {
        unsigned c2;
        c2 = 0xF0 | ((c>>18)&0x03);
        datachain_append_char(dach, name, c2);
        c2 = 0x80 | ((c>>12)&0x3F);
        datachain_append_char(dach, name, c2);
        c2 = 0x80 | ((c>> 6)&0x3F);
        datachain_append_char(dach, name, c2);
        c2 = 0x80 | ((c>> 0)&0x3F);
        datachain_append_char(dach, name, c2);
    } else if (c & ~0x7FF) {
        unsigned c2;
        c2 = 0xE0 | ((c>>12)&0x0F);
        datachain_append_char(dach, name, c2);
        c2 = 0x80 | ((c>> 6)&0x3F);
        datachain_append_char(dach, name, c2);
        c2 = 0x80 | ((c>> 0)&0x3F);
        datachain_append_char(dach, name, c2);
    } else if (c & ~0x7f) {
        unsigned c2;
        c2 = 0xc0 | ((c>> 6)&0x1F);
        datachain_append_char(dach, name, c2);
        c2 = 0x80 | ((c>> 0)&0x3F);
        datachain_append_char(dach, name, c2);
    } else
        datachain_append_char(dach, name, c);
}



/***************************************************************************
 create a data
 NOTE: the name must not exist
 ***************************************************************************/
static struct DataLink *
datachain_new_link(struct DataChain *dach, const char *name)
{
    struct DataLink *p = MALLOC(sizeof(struct DataLink));

    safe_strcpy(p->name, DACH_MAX_NAME_SIZE, name);

    p->name_hash = name_hash(name);
    p->data_size = sizeof(p->data);
    p->data_len  = 0;
    p->next      = dach->link;
    dach->link   = p;

    return p;
}


/***************************************************************************
 ***************************************************************************/
static struct DataLink *
datachain_expand(struct DataChain *dach, struct DataLink *p)
{
    struct DataLink *n;

    /* Double the space */
    n = MALLOC(offsetof(struct DataLink, data) + 2*p->data_size);
    memcpy(n, p, offsetof(struct DataLink, data) + p->data_size);
    n->data_size *= 2;

    n->next = p->next;

    struct DataLink *link = dach->link;

    if (link==p) {
        dach->link = n;
    } else {
        while (link->next != p)
            link = link->next;
        link->next = n;
    }

    free(p);

    return n;
}






/***************************************************************************
 ***************************************************************************/
static void
datachain_vprintf(struct DataChain *dach, const char *name,
    const char *fmt, va_list marker) {

    char str[10];
    int len;
    
    len = vsnprintf(str, sizeof(str), fmt, marker);
    if (len > sizeof(str)-1) {
        char *tmp = MALLOC(len+1);
        vsnprintf(tmp, len+1, fmt, marker);
        datachain_append(dach, name, tmp, len);
        free(tmp);
    } else {
        datachain_append(dach, name, str, len);
    }
}

/***************************************************************************
 ***************************************************************************/
void
datachain_printf(struct DataChain *dach, const char *name, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    datachain_vprintf(dach, name, fmt, marker);
    va_end(marker);
}

/***************************************************************************
 ***************************************************************************/
void
datachain_append(struct DataChain *dach, const char *name, 
    const void *px, size_t length)
{
    struct DataLink *p;

    if (length == AUTO_LEN)
        length = strlen((const char*)px);
    
    p = datachain_find_link(dach, name);
    if (p == NULL) {
        p = datachain_new_link(dach, name);
    }


    /*
     * If the current object isn't big enough, expand it
     */
    while (p->data_len + length >= p->data_size) {
        p = datachain_expand(dach, p);
    }

    
    
    /*
     * Now that we are assured there is enough space, do the copy
     */
    memcpy(p->data + p->data_len, px, length);
    p->data_len = (unsigned)(p->data_len + length);

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
datachain_init_base64(struct DataChainB64 *base64)
{
    base64->state = 0;
    base64->temp = 0;
}

/*****************************************************************************
 *****************************************************************************/
void
datachain_append_base64(struct DataChain *dach, const char *name,
    const void *vpx, size_t length, struct DataChainB64 *base64)
{
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
                datachain_append_char(dach, name, b64[(x>>18)&0x3F]);
                datachain_append_char(dach, name, b64[(x>>12)&0x3F]);
                datachain_append_char(dach, name, b64[(x>> 6)&0x3F]);
                datachain_append_char(dach, name, b64[(x>> 0)&0x3F]);
        }
    }
    
    base64->temp = x;
    base64->state = state;
}

/*****************************************************************************
 *****************************************************************************/
void
datachain_finalize_base64(struct DataChain *dach, const char *name,
    struct DataChainB64 *base64)
{
    unsigned x = base64->temp;
    switch (base64->state) {
        case 0:
            break;
        case 1:
            datachain_append_char(dach, name, b64[(x>>18)&0x3F]);
            datachain_append_char(dach, name, b64[(x>>12)&0x3F]);
            datachain_append_char(dach, name, '=');
            datachain_append_char(dach, name, '=');
            break;
        case 2:
            datachain_append_char(dach, name, b64[(x>>18)&0x3F]);
            datachain_append_char(dach, name, b64[(x>>12)&0x3F]);
            datachain_append_char(dach, name, b64[(x>>6)&0x3F]);
            datachain_append_char(dach, name, '=');
            break;
    }
}



/*****************************************************************************
 *****************************************************************************/
static int
datachain_string_equals(struct DataChain *dach, const char *name, const char *rhs)
{
    const unsigned char *lhs = datachain_string(dach, name);
    size_t lhs_length = datachain_string_length(dach, name);
    size_t rhs_length = strlen(rhs);
    
    if (lhs_length != rhs_length)
        return 0;
    return memcmp(lhs, rhs, rhs_length) == 0;
}

/*****************************************************************************
 *****************************************************************************/
int
datachain_selftest(void)
{
    /*
     * Basic test
     */
    {
        struct DataChain dach[1];
        unsigned i;

        for (i=0; i<10; i++) {
            datachain_append(dach, "x", "xxxx", 4);
            datachain_append(dach, "y", "yyyyy", 5);
        }
        
        if (dach->link == 0)
            return 1;
        if (datachain_string_length(dach, "x") != 40)
            return 1;
        if (datachain_string_length(dach, "y") != 50)
            return 1;
        
        datachain_release(dach);
        if (dach->link != NULL)
            return 1;
    }
    
    /*
     * Test BASE64 encoding. We are going to do strings of various lengths
     * in order to test the boundary condition of finalizing various strings
     * properly
     */
    {
        struct DataChain dach[1];
        struct DataChainB64 base64[1];

        datachain_init_base64(base64);
        datachain_append_base64(dach, "1", "x", 1, base64);
        datachain_finalize_base64(dach, "1", base64);

        datachain_init_base64(base64);
        datachain_append_base64(dach, "2", "bc", 2, base64);
        datachain_finalize_base64(dach, "2", base64);
        
        datachain_init_base64(base64);
        datachain_append_base64(dach, "3", "mno", 3, base64);
        datachain_finalize_base64(dach, "3", base64);
        
        datachain_init_base64(base64);
        datachain_append_base64(dach, "4", "stuv", 4, base64);
        datachain_finalize_base64(dach, "4", base64);
        
        datachain_init_base64(base64);
        datachain_append_base64(dach, "5", "fghij", 5, base64);
        datachain_finalize_base64(dach, "5", base64);
        
        
        if (!datachain_string_equals(dach, "1", "eA=="))
            return 1;
        if (!datachain_string_equals(dach, "2", "YmM="))
            return 1;
        if (!datachain_string_equals(dach, "3", "bW5v"))
            return 1;
        if (!datachain_string_equals(dach, "4", "c3R1dg=="))
            return 1;
        if (!datachain_string_equals(dach, "5", "ZmdoaWo="))
            return 1;

        datachain_release(dach);
    }
    
    
    return 0;
}

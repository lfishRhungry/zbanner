/*
    Data Chain

    This module remembers a series of "name" & "data" identified by id.
    These are often simple strings, like the FTP hello string.

    From masscan's `banout`
    Modified by lishRhungry 2024
*/
#include "data-chain.h"
#include "fine-malloc.h"

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

/***************************************************************************
 ***************************************************************************/
void
datachain_init(struct DataChain *dach)
{
    dach->length     = 0;
    dach->id         = 0;
    dach->next       = 0;
    dach->max_length = sizeof(dach->data);
}

/***************************************************************************
 ***************************************************************************/
void
datachain_release(struct DataChain *dach)
{
    while (dach->next) {
        struct DataChain *next = dach->next->next;
        free(dach->next);
        dach->next = next;
    }
    datachain_init(dach);
}


/***************************************************************************
 ***************************************************************************/
static struct DataChain *
datachain_find_by_id(struct DataChain *dach, unsigned id)
{
    while (dach && dach->id != id)
        dach = dach->next;
    return dach;
}

/***************************************************************************
 ***************************************************************************/
const unsigned char *
datachain_string(const struct DataChain *dach, unsigned id)
{
    while (dach && (dach->id&0xFFFF) != id)
        dach = dach->next;

    if (dach)
        return dach->data;
    else
        return NULL;
}

/***************************************************************************
 ***************************************************************************/
unsigned
datachain_is_equal(const struct DataChain *dach, unsigned id,
                const char *string)
{
    const unsigned char *string2;
    size_t string_length;
    size_t string2_length;

    /*
     * Grab the string
     */
    string2 = datachain_string(dach, id);
    if (string2 == NULL)
        return string == NULL;

    if (string == NULL)
        return 0;
    
    string_length = strlen(string);
    string2_length = datachain_string_length(dach, id);

    if (string_length != string2_length)
        return 0;
    
    return memcmp(string, string2, string2_length) == 0;
}

/***************************************************************************
 ***************************************************************************/
unsigned
datachain_is_contains(const struct DataChain *dach, unsigned id,
                const char *string)
{
    const unsigned char *string2;
    size_t string_length;
    size_t string2_length;
    size_t i;

    /*
     * Grab the string
     */
    string2 = datachain_string(dach, id);
    if (string2 == NULL)
        return string == NULL;

    if (string == NULL)
        return 0;
    
    string_length = strlen(string);
    string2_length = datachain_string_length(dach, id);

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
datachain_string_length(const struct DataChain *dach, unsigned id)
{
    while (dach && dach->id != id)
        dach = dach->next;

    if (dach)
        return dach->length;
    else
        return 0;
}

/***************************************************************************
 ***************************************************************************/
void
datachain_newline(struct DataChain *dach, unsigned id)
{
    struct DataChain *p;

    p = datachain_find_by_id(dach, id);
    if (p && p->length) {
        datachain_append_char(dach, id, '\n');
    }
}

/***************************************************************************
 ***************************************************************************/
void
datachain_end(struct DataChain *dach, unsigned id)
{
    struct DataChain *p;

    p = datachain_find_by_id(dach, id);
    if (p && p->length) {
        p->id |= 0x80000000;
    }
}

/***************************************************************************
 ***************************************************************************/
void
datachain_append_char(struct DataChain *dach, unsigned id, int c)
{
    char cc = (char)c;
    datachain_append(dach, id, &cc, 1);
}

/***************************************************************************
 ***************************************************************************/
void
datachain_append_hexint(struct DataChain *dach, unsigned id, unsigned long long number, int digits)
{
    if (digits == 0) {
        for (digits=16; digits>0; digits--)
            if (number>>((digits-1)*4) & 0xF)
                break;
    }
    
    for (;digits>0; digits--) {
        char c = "0123456789abcdef"[(number>>(unsigned long long)((digits-1)*4)) & 0xF];
        datachain_append_char(dach, id, c);
    }
}

/***************************************************************************
 * Output either a normal character, or the hex form of a UTF-8 string
 ***************************************************************************/
void
datachain_append_unicode(struct DataChain *dach, unsigned id, unsigned c)
{
    if (c & ~0xFFFF) {
        unsigned c2;
        c2 = 0xF0 | ((c>>18)&0x03);
        datachain_append_char(dach, id, c2);
        c2 = 0x80 | ((c>>12)&0x3F);
        datachain_append_char(dach, id, c2);
        c2 = 0x80 | ((c>> 6)&0x3F);
        datachain_append_char(dach, id, c2);
        c2 = 0x80 | ((c>> 0)&0x3F);
        datachain_append_char(dach, id, c2);
    } else if (c & ~0x7FF) {
        unsigned c2;
        c2 = 0xE0 | ((c>>12)&0x0F);
        datachain_append_char(dach, id, c2);
        c2 = 0x80 | ((c>> 6)&0x3F);
        datachain_append_char(dach, id, c2);
        c2 = 0x80 | ((c>> 0)&0x3F);
        datachain_append_char(dach, id, c2);
    } else if (c & ~0x7f) {
        unsigned c2;
        c2 = 0xc0 | ((c>> 6)&0x1F);
        datachain_append_char(dach, id, c2);
        c2 = 0x80 | ((c>> 0)&0x3F);
        datachain_append_char(dach, id, c2);
    } else
        datachain_append_char(dach, id, c);
}



/***************************************************************************
 ***************************************************************************/
static struct DataChain *
datachain_new_data(struct DataChain *dach, unsigned id)
{
    struct DataChain *p;

    if (dach->id == 0 && dach->length == 0) {
        dach->id = id;
        return dach;
    }

    p = CALLOC(1, sizeof(*p));
    p->id = id;
    p->max_length = sizeof(p->data);
    p->next = dach->next;
    dach->next = p;
    return p;
}


/***************************************************************************
 ***************************************************************************/
static struct DataChain *
datachain_expand(struct DataChain *dach, struct DataChain *p)
{
    struct DataChain *n;

    /* Double the space */
    n = MALLOC(offsetof(struct DataChain, data) + 2*p->max_length);
    memcpy(n, p, offsetof(struct DataChain, data) + p->max_length);
    n->max_length *= 2;

    if (p == dach) {
        /* 'p' is the head of the linked list, so we can't free it */
        dach->next = n;
        p->id = 0;
        p->length = 0;
    } else {
        /* 'p' is not the head, so replace it in the list with 'n',
         * then free it. */
        while (dach->next != p)
            dach = dach->next;
        dach->next = n;
        free(p);
    }

    return n;
}






/***************************************************************************
 ***************************************************************************/
static void
datachain_vprintf(struct DataChain *dach, unsigned id,
               const char *fmt, va_list marker) {
    char str[10];
    int len;
    
    len = vsnprintf(str, sizeof(str), fmt, marker);
    if (len > sizeof(str)-1) {
        char *tmp = MALLOC(len+1);
        vsnprintf(tmp, len+1, fmt, marker);
        datachain_append(dach, id, tmp, len);
        free(tmp);
    } else {
        datachain_append(dach, id, str, len);
    }
}

/***************************************************************************
 ***************************************************************************/
void
datachain_printf(struct DataChain *dach, unsigned id, const char *fmt, ...) {
    va_list marker;

    va_start(marker, fmt);
    datachain_vprintf(dach, id, fmt, marker);
    va_end(marker);
}

/***************************************************************************
 ***************************************************************************/
void
datachain_append(struct DataChain *dach, unsigned id, 
              const void *px, size_t length)
{
    struct DataChain *p;

    if (length == AUTO_LEN)
        length = strlen((const char*)px);
    
    p = datachain_find_by_id(dach, id);
    if (p == NULL) {
        p = datachain_new_data(dach, id);
    }


    /*
     * If the current object isn't big enough, expand it
     */
    while (p->length + length >= p->max_length) {
        p = datachain_expand(dach, p);
    }

    
    
    /*
     * Now that we are assured there is enough space, do the copy
     */
    memcpy(p->data + p->length, px, length);
    p->length = (unsigned)(p->length + length);

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
datachain_append_base64(struct DataChain *dach, unsigned id,
                     const void *vpx, size_t length,
                     struct DataChainB64 *base64)
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
                datachain_append_char(dach, id, b64[(x>>18)&0x3F]);
                datachain_append_char(dach, id, b64[(x>>12)&0x3F]);
                datachain_append_char(dach, id, b64[(x>> 6)&0x3F]);
                datachain_append_char(dach, id, b64[(x>> 0)&0x3F]);
        }
    }
    
    base64->temp = x;
    base64->state = state;
}

/*****************************************************************************
 *****************************************************************************/
void
datachain_finalize_base64(struct DataChain *dach, unsigned id,
                       struct DataChainB64 *base64)
{
    unsigned x = base64->temp;
    switch (base64->state) {
        case 0:
            break;
        case 1:
            datachain_append_char(dach, id, b64[(x>>18)&0x3F]);
            datachain_append_char(dach, id, b64[(x>>12)&0x3F]);
            datachain_append_char(dach, id, '=');
            datachain_append_char(dach, id, '=');
            break;
        case 2:
            datachain_append_char(dach, id, b64[(x>>18)&0x3F]);
            datachain_append_char(dach, id, b64[(x>>12)&0x3F]);
            datachain_append_char(dach, id, b64[(x>>6)&0x3F]);
            datachain_append_char(dach, id, '=');
            break;
    }
}



/*****************************************************************************
 *****************************************************************************/
static int
datachain_string_equals(struct DataChain *dach, unsigned id,
                     const char *rhs)
{
    const unsigned char *lhs = datachain_string(dach, id);
    size_t lhs_length = datachain_string_length(dach, id);
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
        
        datachain_init(dach);
        
        for (i=0; i<10; i++) {
            datachain_append(dach, 1, "xxxx", 4);
            datachain_append(dach, 2, "yyyyy", 5);
        }
        
        if (dach->next == 0)
            return 1;
        if (datachain_string_length(dach, 1) != 40)
            return 1;
        if (datachain_string_length(dach, 2) != 50)
            return 1;
        
        datachain_release(dach);
        if (dach->next != 0)
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
    
        datachain_init(dach);

        datachain_init_base64(base64);
        datachain_append_base64(dach, 1, "x", 1, base64);
        datachain_finalize_base64(dach, 1, base64);
        
        datachain_init_base64(base64);
        datachain_append_base64(dach, 2, "bc", 2, base64);
        datachain_finalize_base64(dach, 2, base64);
        
        datachain_init_base64(base64);
        datachain_append_base64(dach, 3, "mno", 3, base64);
        datachain_finalize_base64(dach, 3, base64);
        
        datachain_init_base64(base64);
        datachain_append_base64(dach, 4, "stuv", 4, base64);
        datachain_finalize_base64(dach, 4, base64);
        
        datachain_init_base64(base64);
        datachain_append_base64(dach, 5, "fghij", 5, base64);
        datachain_finalize_base64(dach, 5, base64);
        
        
        if (!datachain_string_equals(dach, 1, "eA=="))
            return 1;
        if (!datachain_string_equals(dach, 2, "YmM="))
            return 1;
        if (!datachain_string_equals(dach, 3, "bW5v"))
            return 1;
        if (!datachain_string_equals(dach, 4, "c3R1dg=="))
            return 1;
        if (!datachain_string_equals(dach, 5, "ZmdoaWo="))
            return 1;

        datachain_release(dach);
    }
    
    
    return 0;
}

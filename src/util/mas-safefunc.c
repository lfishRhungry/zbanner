/*
    safe C library functions

    This upgrades unsafe C functions like "strcpy()" to safer equivalents,
    like "safe_strcpy()".

    NOTE: This is for maintaining a policy of "no unsafe functions"
*/
#include "mas-safefunc.h"
#include <errno.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

/**
 * Case-insensitive memcmp()
 */
#ifdef __GNUC__
int
memcasecmp(const void *lhs, const void *rhs, size_t length)
{
    int i;
    for (i=0; i<length; i++) {
        if (tolower(((char*)lhs)[i]) != tolower(((char*)rhs)[i]))
            return -1;
    }
    return 0;
}
#endif

/**
 * Safe version of `strcpy()`
 */
void
safe_strcpy(char *dst, size_t sizeof_dst, const char *src)
{
    size_t i;

    if (sizeof_dst == 0)
        return;

    if (dst == NULL)
        return;

    if (src == NULL) {
        dst[0] = 0;
        return;
    }

    for (i=0; src[i]; i++) {
        if (i >= sizeof_dst) {
            dst[0] = 0;
            return;
        } else
            dst[i] = src[i];
    }
    if (i >= sizeof_dst) {
        dst[0] = 0;
        return ;
    } else
        dst[i] = src[i];

    return;
}



int
safe_localtime(struct tm* _tm, const time_t *time)
{
    struct tm *x;

    x = localtime(time);
    if (x == NULL) {
        memset(_tm, 0, sizeof(*_tm));
        return -1;
    }
    memcpy(_tm, x, sizeof(*_tm));

    return 0;
}


int
safe_gmtime(struct tm* _tm, const time_t *time)
{
    struct tm *x;

    x = gmtime(time);
    if (x == NULL) {
        memset(_tm, 0, sizeof(*_tm));
        return -1;
    }
    memcpy(_tm, x, sizeof(*_tm));

    return 0;
}

char *
stristr (const char * haystack, const char * needle)
{
    char *cp = (char *) haystack;
    char *s1, *s2;
    
    if (!*needle)
        return((char *)haystack);
    
    while (*cp) {
        s1 = cp;
        s2 = (char *) needle;
        
        while (*s1 && *s2 && toupper(*s1)==toupper(*s2) ) {
            s1++, s2++;
        }
        
        if (!*s2) return(cp);
        
        cp++;
    }
    
    return(NULL);
}

void *
safe_memismem (const void * haystack, size_t haystacklen,
    const void * needle, size_t needlelen)
{
    char *cp = (char *) haystack;
    char *s1, *s2;
    
    while (*cp) {
        s1 = cp;
        s2 = (char *) needle;
        
        while ((s1-(char *)haystack)!=haystacklen
            && (s2-(char *)needle)!=needlelen
            && toupper(*s1)==toupper(*s2) ) {
            s1++, s2++;
        }
        
        if ((s2-(char *)needle)==needlelen) return(cp);
        
        cp++;
    }
    
    return(NULL);
}

void
trim(char *line, size_t sizeof_line)
{
    if (sizeof_line > strlen(line))
        sizeof_line = strlen(line);

    while (isspace(*line & 0xFF))
        memmove(line, line+1, sizeof_line--);
    while (*line && isspace(line[sizeof_line-1] & 0xFF))
        line[--sizeof_line] = '\0';
}

const char *
normalize_string(const unsigned char *px, size_t length,
    char *buf, size_t buf_len)
{
    size_t i=0;
    size_t offset = 0;


    for (i=0; i<length; i++) {
        unsigned char c = px[i];

        if (isprint(c) && c != '<' && c != '>' && c != '&' && c != '\\' && c != '\"' && c != '\'') {
            if (offset + 2 < buf_len)
                buf[offset++] = px[i];
        } else {
            if (offset + 5 < buf_len) {
                buf[offset++] = '\\';
                buf[offset++] = 'x';
                buf[offset++] = "0123456789abcdef"[px[i]>>4];
                buf[offset++] = "0123456789abcdef"[px[i]&0xF];
            }
        }
    }

    buf[offset] = '\0';

    return buf;
}

void *
safe_memmem(const void *src,int srclen,const void *trg,int trglen)
{
    unsigned char *csrc = (unsigned char *)src;
    unsigned char *ctrg = (unsigned char *)trg;
    unsigned char *tptr,*cptr;
    int searchlen,ndx=0;

    /* add some initial error checking if you want */

    while (ndx<=srclen) {
        cptr = &csrc[ndx];
        if ((searchlen = srclen-ndx-trglen+1) <= 0) {
            return NULL;
        } /* if */
        if ((tptr = memchr(cptr,*ctrg,searchlen)) == NULL) {
            return NULL;
        } /* if */
        if (memcmp(tptr,ctrg,trglen) == 0) {
            return tptr;
        } /* if */
        ndx += tptr-cptr+1;
    } /* while */

    return NULL;
}
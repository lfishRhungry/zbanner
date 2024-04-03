#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "xprint.h"

void xprint(const char *text, unsigned indent, unsigned count)
{
    size_t len = strlen(text);
    if (len==0) return;
    if (count==0) return;
    if (count<=indent) return;

    /*count in one line*/
    unsigned c = 0;
    for (unsigned i=0; i<len; i++) {
        if (c==0) {
            printf("%*s", indent, "");
            c += indent;
        }

        if (c==indent) {
            /*no space in head of line*/
            if (text[i]==' ') {
                continue;
            }
        }

        /*proper split the word in the end of line*/
        // if (c==count-2) {
        //     if (isalnum(text[i]) && i<len-1 && isalnum(text[i+1])) {
        //         printf("%c-\n",text[i]);
        //         printf("%*s-", indent, "");
        //         c = 1+indent;
        //         continue;
        //     }
        //     if (text[i]==' ' && i<len-1 && isalnum(text[i+1])) {
        //         printf("  \n%*s", indent, "");
        //         c = indent;
        //         continue;
        //     }
        // }

        if (text[i]=='\n') {
            printf("\n%*s", indent, "");
            c = indent;
        } else {
            printf("%c", text[i]);
            c++;
        }

        if (c==count) {
            printf("\n");
            c = 0;
        }
    }
}

void xprint_with_head(const char *text, unsigned indent, unsigned count)
{
    size_t len = strlen(text);
    if (len==0) return;
    if (count==0) return;
    if (count<=indent) return;

    /*count in one line*/
    unsigned c = 0;
    for (unsigned i=0; i<len; i++) {
        if (c==0) {
            printf("%*s", indent, "");
            c += indent;
        }

        // if (c==indent) {
        //     /*no space in head of line*/
        //     if (text[i]==' ') {
        //         continue;
        //     }
        // }

        /*proper split the word in the end of line*/
        // if (c==count-2) {
        //     if (isalnum(text[i]) && i<len-1 && isalnum(text[i+1])) {
        //         printf("%c-\n",text[i]);
        //         printf("%*s-", indent, "");
        //         c = 1+indent;
        //         continue;
        //     }
        //     if (text[i]==' ' && i<len-1 && isalnum(text[i+1])) {
        //         printf("  \n%*s", indent, "");
        //         c = indent;
        //         continue;
        //     }
        // }

        if (text[i]=='\n') {
            printf("\n%*s", indent, "");
            c = indent;
        } else {
            printf("%c", text[i]);
            c++;
        }

        if (c==count) {
            printf("\n");
            c = 0;
        }
    }
}
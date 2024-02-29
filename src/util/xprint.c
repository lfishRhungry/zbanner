#include <stdio.h>
#include <string.h>

#include "xprint.h"

void print_with_indent(const char *text, unsigned indent, unsigned count)
{
    size_t len = strlen(text);
    if (len==0) return;
    if (count==0) return;
    if (count<=indent) return;

    unsigned c = 0;
    for (unsigned i=0; i<len; i++) {
        if (c==0) {
            printf("%*s", indent, "");
            c += indent;
        }
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
#ifndef XPRINT_H
#define XPRINT_H

#define XPRINT_DASH_LINE                                                       \
    "------------------------------------------------------------------------" \
    "--------"
#define XPRINT_EQUAL_LINE                                                      \
    "========================================================================" \
    "========"
#define XPRINT_STAR_LINE                                                       \
    "************************************************************************" \
    "********"
#define XPRINT_SHARP_LINE                                                      \
    "########################################################################" \
    "########"

#define XPRINT_CH_COLOR_RED     "\x1b[31m"
#define XPRINT_CH_COLOR_GREEN   "\x1b[32m"
#define XPRINT_CH_COLOR_YELLOW  "\x1b[33m"
#define XPRINT_CH_COLOR_BLUE    "\x1b[34m"
#define XPRINT_CH_COLOR_MAGENTA "\x1b[35m"
#define XPRINT_CH_COLOR_CYAN    "\x1b[36m"

#define XPRINT_BG_COLOR_RED     "\x1b[41m"
#define XPRINT_BG_COLOR_GREEN   "\x1b[42m"
#define XPRINT_BG_COLOR_YELLOW  "\x1b[43m"
#define XPRINT_BG_COLOR_BLUE    "\x1b[44m"
#define XPRINT_BG_COLOR_MAGENTA "\x1b[45m"
#define XPRINT_BG_COLOR_CYAN    "\x1b[46m"

#define XPRINT_COLOR_RESET "\x1b[0m"

/*print documents with an indent*/
void xprint(const char *text, unsigned indent, unsigned count);

/*keep spaces in the head of line*/
void xprint_with_head(const char *text, unsigned indent, unsigned count);

#endif
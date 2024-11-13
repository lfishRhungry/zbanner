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

/*font color*/
#define XPRINT_CH_COLOR_RED     "\033[31m"
#define XPRINT_CH_COLOR_GREEN   "\033[32m"
#define XPRINT_CH_COLOR_YELLOW  "\033[33m"
#define XPRINT_CH_COLOR_BLUE    "\033[34m"
#define XPRINT_CH_COLOR_MAGENTA "\033[35m"
#define XPRINT_CH_COLOR_CYAN    "\033[36m"
/*background color*/
#define XPRINT_BG_COLOR_RED     "\033[41m"
#define XPRINT_BG_COLOR_GREEN   "\033[42m"
#define XPRINT_BG_COLOR_YELLOW  "\033[43m"
#define XPRINT_BG_COLOR_BLUE    "\033[44m"
#define XPRINT_BG_COLOR_MAGENTA "\033[45m"
#define XPRINT_BG_COLOR_CYAN    "\033[46m"
/*controlling*/
#define XPRINT_RESET            "\033[0m"
#define XPRINT_BOLD             "\033[1m"
#define XPRINT_ITALIC           "\033[3m"
#define XPRINT_UNDERLINE        "\033[4m"
#define XPRINT_LINE_UP          "\033[A"
#define XPRINT_LINE_DOWN        "\033[B"
#define XPRINT_COLUMN_RIGHT     "\033[C"
#define XPRINT_COLUMN_LEFT      "\033[D"
#define XPRINT_CLEAR_SCREEN     "\033[2J"
#define XPRINT_CLEAR_LINE       "\033[K" /*clear contents after the cursor*/

/*print documents with an indent*/
void xprint(const char *text, unsigned indent, unsigned count);

/*keep spaces in the head of line*/
void xprint_with_head(const char *text, unsigned indent, unsigned count);

#endif
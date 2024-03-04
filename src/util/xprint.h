#ifndef XPRINT_H
#define XPRINT_H

#define XPRINT_DASH_LINE     "--------------------------------------------------------------------------------"
#define XPRINT_EQUAL_LINE    "================================================================================"
#define XPRINT_STAR_LINE     "********************************************************************************"
#define XPRINT_SHARP_LINE    "################################################################################"

/*print documents with an indent*/
void xprint(const char *text, unsigned indent, unsigned count);

/*keep spaces in the head of line*/
void xprint_with_head(const char *text, unsigned indent, unsigned count);

#endif
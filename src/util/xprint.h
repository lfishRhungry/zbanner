#ifndef XPRINT_H
#define XPRINT_H

#define XPRINT_DASH_LINE     "--------------------------------------------------------------------------------"
#define XPRINT_EQUAL_LINE    "================================================================================"
#define XPRINT_STAR_LINE     "********************************************************************************"
#define XPRINT_SHARP_LINE    "################################################################################"

void print_with_indent(const char *text, unsigned indent, unsigned count);

#endif
#ifndef BOOL_H
#define BOOL_H

#if _MSC_VER && _MSC_VER < 1800
typedef enum {false=0, true=1} bool;
#else
#include <stdbool.h>
#endif
#endif


#ifndef GLOBALS_H
#define GLOBALS_H
#include <time.h>

extern time_t                     global_now;
extern unsigned volatile          time_to_finish_tx;
extern unsigned volatile          time_to_finish_rx;
extern struct TemplateSet        *global_tmplset;


#endif

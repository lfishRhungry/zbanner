#ifndef GLOBALS_H
#define GLOBALS_H
#include <time.h>

extern time_t              global_now;
extern unsigned volatile   is_tx_done;
extern unsigned volatile   is_rx_done;
extern struct TemplateSet *global_tmplset;


#endif

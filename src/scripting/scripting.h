/*
    Xconf scripting subsystem
*/
#ifndef SCRIPTING_H
#define SCRIPTING_H
#include "../proto/proto-banner1.h"
struct Xconf;

extern const struct ProtocolParserStream banner_scripting;

/**
 * Load the Lua scripting library and run the initialization
 * stage of all the specified scripts
 */
void scripting_init(struct Xconf *xconf);

/**
 * Create the "Xconf" object within the scripting subsystem
 */
void scripting_xconf_init(struct Xconf *xconf);

#endif


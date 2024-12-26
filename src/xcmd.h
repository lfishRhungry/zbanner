/**
 * Use crossline lib to simulate an interactive command mode.
 *
 * Created by sharkocha 2024
 */
#ifndef XCMD_H
#define XCMD_H

#include "xconf.h"

/**
 * get into interactive mode to set params.
 */
void xcmd_interactive_readline(XConf *xconf);

/**
 * reboot our executable in processs for interactive mode on Linux.
 *
 * @param path path of our executable
 * @param conf path of conf file
 * @return zero if success or on Windows. 1 if invalid path. -1 if reboot error.
 */
int xcmd_reboot_for_interact(const char *path, const char *conf);

#endif
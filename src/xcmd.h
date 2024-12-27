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
void xcmd_interactive_readline(XConf *xconf, const char *exe_path);

/**
 * reboot our executable in processs for interactive mode on Linux.
 *
 * @param path path of our executable
 * @param conf path of conf file
 * @return zero if success or on Windows. 1 if invalid path. -1 if reboot error.
 */
int xcmd_reboot_for_interact(const char *path, const char *conf);

/**
 * If we are in interactive mode, try to reboot in interactive mode again, and
 * try to load saved conf.
 * @return never return if successed.
 */
void xcmd_try_reboot();

#endif
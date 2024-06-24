/*
    PF_RING compatibility layer

    In order to avoid special build hassle, this code links to PF_RING at
    runtime instead compile-time. That means you can compile this code
    BEFORE installing and building PF_RING.

*/
#include "stub-pfring.h"
#include "../util-data/safe-string.h"
#include "../util-out/logger.h"

struct PFRING PFRING;

#if defined(__linux__)
#include <dlfcn.h>
#endif

/***************************************************************************
 * This checks whether the "pf_ring" driver is installed.
 ***************************************************************************/
int
PFRING_is_installed(void);

int
PFRING_is_installed(void)
{
#if defined(__linux__)
    FILE *fp;
    char line[256];
    int found = 0;

    fp = fopen("/proc/modules", "rb");
    if (fp == NULL)
        return 0;

    while (fgets(line, sizeof(line), fp)) {
        if (memcmp(line, "pf_ring ", 8) == 0) {
            found = 1;
            LOG(LEVEL_DETAIL, "pfring: found 'pf_ring' driver\n");
        }
        if (memcmp(line, "ixgbe ", 6) == 0) {
            LOG(LEVEL_DETAIL, "pfring: found 'ixgbe' driver\n");
        }
        if (memcmp(line, "e1000e ", 8) == 0) {
            LOG(LEVEL_DETAIL, "pfring: found 'e1000e' driver\n");
        }
    }
    fclose(fp);
    return found;
#else
    return 0;
#endif
}


/***************************************************************************
 ***************************************************************************/
int
PFRING_init(void)
{
#if defined(__linux__)
    void *h;
    int err = 0;
    LOG(LEVEL_DETAIL, "pfring: initializing subsystem\n");
    LOG(LEVEL_DETAIL, "pfring: looking for 'libpfring.so'\n");
    h = dlopen("libpfring.so", RTLD_LAZY);
    if (h == NULL) {
        LOG(LEVEL_WARN, "pfring: dlopen('libpfring.so'): %s\n", strerror(errno));
        return 0;
    } else
        LOG(LEVEL_DETAIL, "pfring: found 'libpfring.so'!\n");

#define LOADSYM(name) if ((PFRING.name = dlsym(h, "pfring_"#name)) == 0) {LOG(LEVEL_WARN, "pfring_%s: not found in 'libpfring.so': %s\n", #name, strerror(errno));err=1;}
    LOADSYM(open);
    LOADSYM(close);
    LOADSYM(enable_ring);
    LOADSYM(send);
    LOADSYM(flush);
    LOADSYM(recv);
    LOADSYM(poll);
    LOADSYM(version);
    LOADSYM(set_direction);
    LOADSYM(set_application_name);
    //LOADSYM(get_bound_device);

    if (err) {
        memset(&PFRING, 0, sizeof(PFRING));
        LOG(LEVEL_WARN, "pfring: failed to load\n");
    } else {
        LOG(LEVEL_INFO, "pfring: successfully loaded PF_RING API\n");

        if (!PFRING_is_installed()) {
            LOG(LEVEL_ERROR, "pfring: ERROR: 'pf_ring' driver module not found!!!!!\n");
        } else
            LOG(LEVEL_DETAIL, "pfring: found 'pf_ring' driver module\n");
    }

#endif
    return 0;
}






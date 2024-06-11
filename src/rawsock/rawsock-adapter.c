#include "rawsock.h"
#include "rawsock-adapter.h"
#include "../stub/stub-pcap.h"
#include "../util-data/fine-malloc.h"

/***************************************************************************
 ***************************************************************************/
struct AdapterCache *
rawsock_init_cache(bool is_sendq)
{
    struct AdapterCache *acache = CALLOC(1, sizeof(struct AdapterCache));
#if defined(WIN32)
    if (is_sendq) {
        acache->sendq = PCAP.sendqueue_alloc(SENDQ_SIZE);
    }
#endif
    return acache;
}

void
rawsock_close_cache(struct AdapterCache *acache)
{
    if (acache->sendq) {
        PCAP.sendqueue_destroy(acache->sendq);
    }

    free(acache);
}

/***************************************************************************
 ***************************************************************************/
int
stack_if_datalink(struct Adapter *adapter)
{
    if (adapter->ring)
        return 1; /* ethernet */
    else {
        return adapter->link_type;
    }
}

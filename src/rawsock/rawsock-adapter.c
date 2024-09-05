#include "rawsock.h"
#include "rawsock-adapter.h"
#include "../stub/stub-pcap.h"
#include "../stub/stub-pcap-dlt.h"
#include "../util-data/fine-malloc.h"

/***************************************************************************
 ***************************************************************************/
AdapterCache *rawsock_init_cache(bool is_sendq) {
    AdapterCache *acache = CALLOC(1, sizeof(AdapterCache));
#if defined(WIN32)
    if (is_sendq) {
        acache->sendq = PCAP.sendqueue_alloc(SENDQ_SIZE);
    }
#endif
    return acache;
}

void rawsock_close_cache(AdapterCache *acache) {
    if (acache->sendq) {
        PCAP.sendqueue_destroy(acache->sendq);
    }

    FREE(acache);
}

/***************************************************************************
 ***************************************************************************/
int stack_if_datalink(Adapter *adapter) {
    if (adapter->ring)
        return PCAP_DLT_ETHERNET;
    else {
        return adapter->link_type;
    }
}

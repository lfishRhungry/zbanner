/*
    get default route (gateway) IPv4 address of the named network
    interface/adapter (like "eth0").

    This works on both Linux and windows.
*/
#include "rawsock.h"
#include "../util-data/safe-string.h"
#include "../util-out/logger.h"

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) ||       \
    defined(__OpenBSD__) || defined(__sun__)
#include <unistd.h>
#include <sys/socket.h>
#include <net/route.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <ctype.h>

#define ROUNDUP2(a, n) ((a) > 0 ? (1 + (((a) - 1U) | ((n) - 1))) : (n))

#if defined(__APPLE__)
#define ROUNDUP(a) ROUNDUP2((a), sizeof(int))
#elif defined(__NetBSD__)
#define ROUNDUP(a) ROUNDUP2((a), sizeof(uint64_t))
#elif defined(__FreeBSD__)
#define ROUNDUP(a) ROUNDUP2((a), sizeof(int))
#elif defined(__OpenBSD__)
#define ROUNDUP(a) ROUNDUP2((a), sizeof(int))
#else
#error unknown platform
#endif

static struct sockaddr *get_rt_address(struct rt_msghdr *rtm, int desired) {
    int              i;
    int              bitmask = rtm->rtm_addrs;
    struct sockaddr *sa      = (struct sockaddr *)(rtm + 1);

    for (i = 0; i < RTAX_MAX; i++) {
        if (bitmask & (1 << i)) {
            if ((1 << i) == desired)
                return sa;
            sa = (struct sockaddr *)(ROUNDUP(sa->sa_len) + (char *)sa);
        } else
            ;
    }
    return NULL;
}

int rawsock_get_default_interface(char *ifname, size_t sizeof_ifname) {
    int               fd;
    int               seq = (int)time(0);
    ssize_t           err;
    struct rt_msghdr *rtm;
    size_t            sizeof_buffer;

    /*
     * Requests/responses from the kernel are done with an "rt_msghdr"
     * structure followed by an array of "sockaddr" structures.
     */
    sizeof_buffer = sizeof(*rtm) + 512;
    rtm           = CALLOC(1, sizeof_buffer);

    /*
     * Create a socket for querying the kernel
     */
    fd = socket(AF_ROUTE, SOCK_RAW, 0);
    if (fd < 0) {
        LOGPERROR("socket(PF_ROUTE)");
        FREE(rtm);
        return errno;
    }
    LOG(LEVEL_DETAIL, "(getif) got socket handle\n");

    /* Needs a timeout. Sometimes it'll hang indefinitely waiting for a
     * response that will never arrive */
    {
        struct timeval timeout;
        timeout.tv_sec  = 1;
        timeout.tv_usec = 0;

        err = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                         sizeof(timeout));
        if (err < 0)
            LOGPERROR("setsockopt(SO_RCVTIMEO)")

        err = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                         sizeof(timeout));
        if (err < 0)
            LOGPERROR("setsockopt(SO_SNDTIMEO)")
    }

    /*
     * Format and send request to kernel
     */
    rtm->rtm_msglen  = sizeof(*rtm) + sizeof(struct sockaddr_in);
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_flags   = RTF_UP;
    rtm->rtm_type    = RTM_GET;
    rtm->rtm_addrs   = RTA_DST | RTA_IFP;
    rtm->rtm_pid     = getpid();
    rtm->rtm_seq     = seq;

    /*
     * Create an empty address of 0.0.0.0
     */
    {
        struct sockaddr_in *sin;
        sin                  = (struct sockaddr_in *)(rtm + 1);
        sin->sin_len         = sizeof(*sin);
        sin->sin_family      = AF_INET;
        sin->sin_addr.s_addr = 0;
    }

    err = write(fd, (char *)rtm, rtm->rtm_msglen);
    if (err <= 0) {
        LOGPERROR("write");
        goto fail;
    }

    /*
     * Read responses until we find one that belongs to us
     */
    for (;;) {
        err = read(fd, (char *)rtm, sizeof_buffer);
        if (err <= 0) {
            LOGPERROR("read");
            goto fail;
        }

        LOG(LEVEL_DETAIL, "(getif) got response, len=%d\n", err);

        if (rtm->rtm_seq != seq) {
            printf("seq: %u %u\n", rtm->rtm_seq, seq);
            continue;
        }
        if (rtm->rtm_pid != getpid()) {
            printf("pid: %u %u\n", rtm->rtm_pid, getpid());
            continue;
        }
        break;
    }
    close(fd);
    fd = -1;

    /*
     * Parse our data
     */
    {
        struct sockaddr_dl *sdl;

        sdl = (struct sockaddr_dl *)get_rt_address(rtm, RTA_IFP);
        if (sdl) {
            size_t len = sdl->sdl_nlen;
            if (len > sizeof_ifname - 1)
                len = sizeof_ifname - 1;
            memcpy(ifname, sdl->sdl_data, len);
            ifname[len] = 0;
            FREE(rtm);
            return 0;
        }
    }

fail:
    FREE(rtm);
    if (fd > 0)
        close(fd);
    return -1;
}

#elif defined(__linux__)
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

struct route_info {
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    int            priority;
    char           ifName[IF_NAMESIZE];
};

static int read_netlink(int fd, char *bufPtr, size_t sizeof_buffer, int seqNum,
                        int pId) {
    struct nlmsghdr *nlHdr;
    int              readLen = 0, msgLen = 0;

    do {
        /* Receive response from the kernel */
        if ((readLen = recv(fd, bufPtr, sizeof_buffer - msgLen, 0)) < 0) {
            LOGPERROR("recv");
            return -1;
        }

        nlHdr = (struct nlmsghdr *)bufPtr;

        /* Check if the header is valid */
        if ((NLMSG_OK(nlHdr, readLen) == 0) ||
            (nlHdr->nlmsg_type == NLMSG_ERROR)) {
            LOGPERROR("NLMSG_OK");
            return -1;
        }

        /* Check if the its the last message */
        if (nlHdr->nlmsg_type == NLMSG_DONE) {
            break;
        } else {
            /* Else move the pointer to buffer appropriately */
            bufPtr += readLen;
            msgLen += readLen;
        }

        /* Check if its a multi part message */
        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
            /* return if its not */
            break;
        }
    } while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

    return msgLen;
}

/* For parsing the route info returned */
static int parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo) {
    struct rtmsg  *rtMsg;
    struct rtattr *rtAttr;
    int            rtLen = 0;

    rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);

    /* This must be an IPv4 (AF_INET) route */
    if (rtMsg->rtm_family != AF_INET)
        return 1;

    /* This must be in main routing table */
    if (rtMsg->rtm_table != RT_TABLE_MAIN)
        return 1;

    /* Attributes field*/
    rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
    rtLen  = RTM_PAYLOAD(nlHdr);
#define FORMATADDR(n)                                                          \
    ((n) & 0xFF), ((n >> 8) & 0xFF), ((n >> 16) & 0xFF), ((n >> 24) & 0xFF)
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
            case RTA_OIF:
                if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
                // LOG(LEVEL_DETAIL, "ifname=%s ", rtInfo->ifName);
                break;
            case RTA_GATEWAY:
                rtInfo->gateWay.s_addr = *(u_int *)RTA_DATA(rtAttr);
                // LOG(LEVEL_DETAIL, "gw=%u.%u.%u.%u ",
                // FORMATADDR(rtInfo->gateWay.s_addr));
                break;
            case RTA_PREFSRC:
                rtInfo->srcAddr.s_addr = *(u_int *)RTA_DATA(rtAttr);
                // LOG(LEVEL_DETAIL, "src=%u.%u.%u.%u ",
                // FORMATADDR(rtInfo->srcAddr.s_addr));
                break;
            case RTA_DST:
                rtInfo->dstAddr.s_addr = *(u_int *)RTA_DATA(rtAttr);
                // LOG(LEVEL_DETAIL, "dst=%u.%u.%u.%u ",
                // FORMATADDR(rtInfo->dstAddr.s_addr));
                break;
            case RTA_PRIORITY:
                rtInfo->priority = *(int *)RTA_DATA(rtAttr);
                // LOG(LEVEL_DETAIL, "priority=0x%08x ", rtInfo->priority);
                break;
            default:
                // LOG(LEVEL_DETAIL, "rta_type=%d ", rtAttr->rta_type)
                ;
        }
    }
    // LOG(LEVEL_DETAIL, "\n");

    return 0;
}

int rawsock_get_default_interface(char *ifname, size_t sizeof_ifname) {
    int              fd;
    struct nlmsghdr *nlMsg;
    char             msgBuf[16384] = {0};
    int              len;
    int              msgSeq   = 0;
    unsigned         ipv4     = 0;
    int              priority = 0x7FFFFF;

    /*
     * Create 'netlink' socket to query kernel
     */
    fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd < 0) {
        LOG(LEVEL_ERROR, "%s:%d: socket(NETLINK_ROUTE): %d\n", __FILE__,
            __LINE__, errno);
        return errno;
    }

    /*
     * format the netlink buffer
     */
    nlMsg = (struct nlmsghdr *)msgBuf;

    nlMsg->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlMsg->nlmsg_type  = RTM_GETROUTE;
    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nlMsg->nlmsg_seq   = msgSeq++;
    nlMsg->nlmsg_pid   = getpid();

    /*
     * send first request to kernel
     */
    if (send(fd, nlMsg, nlMsg->nlmsg_len, 0) < 0) {
        LOG(LEVEL_ERROR, "%s:%d: send(NETLINK_ROUTE): %d\n", __FILE__, __LINE__,
            errno);
        return errno;
    }

    /*
     * Now read all the responses
     */
    len = read_netlink(fd, msgBuf, sizeof(msgBuf), msgSeq, getpid());
    if (len <= 0) {
        LOG(LEVEL_ERROR, "%s:%d: read_netlink: %d\n", __FILE__, __LINE__,
            errno);
        return errno;
    }

    /*
     * Parse the response
     */
    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
        struct route_info rtInfo[1] = {
            {.dstAddr = {0}, .srcAddr = {0}, .gateWay = {0}}};
        int err;

        // LOG(LEVEL_DETAIL, "if: nlmsg_type=%d nlmsg_flags=0x%x\n",
        // nlMsg->nlmsg_type, nlMsg->nlmsg_flags);
        err = parseRoutes(nlMsg, rtInfo);
        if (err != 0)
            continue;

        LOG(LEVEL_DETAIL,
            "if: route: '%12s' dst=%u.%u.%u.%u src=%u.%u.%u.%u gw=%u.%u.%u.%u "
            "priority=%d\n",
            rtInfo->ifName, FORMATADDR(rtInfo->dstAddr.s_addr),
            FORMATADDR(rtInfo->srcAddr.s_addr),
            FORMATADDR(rtInfo->gateWay.s_addr), rtInfo->priority);

        /* make sure destination = 0.0.0.0 for "default route" */
        if (rtInfo->dstAddr.s_addr != 0)
            continue;

        /* found the gateway! */
        if (rtInfo->priority < priority) {
            priority = rtInfo->priority;
            ipv4     = ntohl(rtInfo->gateWay.s_addr);
            if (ipv4 == 0)
                continue;
            safe_strcpy(ifname, sizeof_ifname, rtInfo->ifName);
        }
    }

    close(fd);

    return 0;
}

#endif

#if defined(_WIN32)
/* From:
 * https://stackoverflow.com/questions/10972794/undefined-reference-to-getadaptersaddresses20-but-i-included-liphlpapi
 * I think this fixed issue #734
 */
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x501
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x501
#endif

#include <winsock2.h>
#include <iphlpapi.h>

#include "../target/target-parse.h"
#include "../util-data/fine-malloc.h"

#ifdef _MSC_VER
#pragma comment(lib, "IPHLPAPI.lib")
#endif

int rawsock_get_default_interface(char *ifname, size_t sizeof_ifname) {
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD            err;
    ULONG            ulOutBufLen = sizeof(IP_ADAPTER_INFO);

    /*
     * Allocate a proper sized buffer
     */
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        LOG(LEVEL_ERROR, "(%s:%u) out of memory.\n", __func__, __LINE__);
        return EFAULT;
    }

    /*
     * Query the adapter info. If the buffer is not big enough, loop around
     * and try again
     */
again:
    err = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    if (err == ERROR_BUFFER_OVERFLOW) {
        FREE(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            LOG(LEVEL_ERROR, "(%s:%u) out of memory.\n", __func__, __LINE__);
            return EFAULT;
        }
        goto again;
    }
    if (err != NO_ERROR) {
        LOG(LEVEL_ERROR, "GetAdaptersInfo failed: %u\n", (unsigned)err);
        return EFAULT;
    }

    /*
     * loop through all adapters looking for ours
     */
    for (pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next) {
        unsigned ipv4 = 0;

        if (pAdapter->Type != MIB_IF_TYPE_ETHERNET &&
            pAdapter->Type != 71 /*wifi*/)
            continue;

        /* See if this adapter has a default-route/gateway configured */
        {
            const IP_ADDR_STRING *addr;

            for (addr = &pAdapter->GatewayList; addr; addr = addr->Next) {
                unsigned x;

                x = target_parse_ipv4(addr->IpAddress.String);
                if (x != 0xFFFFFFFF) {
                    ipv4 = x;
                    break;
                }
            }
        }

        /*
         * When we reach the first adapter with an IP address, then
         * we'll use that one
         */
        if (ipv4) {
            snprintf(ifname, sizeof_ifname, "\\Device\\NPF_%s",
                     pAdapter->AdapterName);
        }
    }
    FREE(pAdapterInfo);

    return 0;
}

#endif

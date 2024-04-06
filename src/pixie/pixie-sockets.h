#ifndef PIXIE_SOCKETS_H
#define PIXIE_SOCKETS_H
#include <stddef.h>
#if defined(WIN32)
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
typedef int SOCKET;
#endif


#endif

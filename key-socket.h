#ifndef _KEY_SOCKET_H_
#define _KEY_SOCKET_H_

/* wolfSSL includes */
#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h> /* included for options sync for cross-compile */
#endif
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* configuration */
#define TCP_WINDOW_SIZE (2 * 128)


/* Socket mappings */
#ifdef HAVE_NETX
    #ifdef NEED_THREADX_TYPES
        #include "types.h"
    #endif
    #include "nx_api.h"
    #ifdef PGB000
        #include "pgb000_com.h"
    #else
        #include "pgb002_ap2.h"
    #endif

    #define KS_SOCKET_T        NX_TCP_SOCKET*
    #define KS_SOCKET_T_INIT   NULL

    #define SOCK_STREAM     1
    #define SOCK_DGRAM      2
    #define IPPROTO_TCP     6
    #define IPPROTO_UDP     17
    #define IPPROTO_IP      0

    #define AF_INET         2
    #define AF_INET6        3

    struct sockaddr {
        unsigned short sa_family;
        unsigned char  sa_data[14];
    };

    struct in_addr {
        unsigned long s_addr;
    };

    struct sockaddr_in {
        unsigned short        sin_family;
        unsigned short        sin_port;
        struct in_addr  sin_addr;
        char            sin_zero[8];
    };

    typedef int socklen_t;
    #define INADDR_ANY 0x00000000UL
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <errno.h>
    #include <arpa/inet.h>
    #include <signal.h>
    #include <unistd.h>
    #include <fcntl.h>

    #define KS_SOCKET_T        int
    #define KS_SOCKET_T_INIT   -1

    #define SOCKET_EWOULDBLOCK EWOULDBLOCK
    #define SOCKET_EAGAIN      EAGAIN
    #define SOCKET_ECONNRESET  ECONNRESET
    #define SOCKET_EINTR       EINTR
    #define SOCKET_EPIPE       EPIPE
    #define SOCKET_ECONNREFUSED ECONNREFUSED
    #define SOCKET_ECONNABORTED ECONNABORTED
#endif

#ifndef IP_ADDRESS
    #define IP_ADDRESS(d, c, b, a) ((((unsigned long) a) << 24) | (((unsigned long) b) << 16) | (((unsigned long) c) << 8) | ((unsigned long) d))
#endif


typedef struct KeySockIoCallback {
    KS_SOCKET_T sockFd;
} KeySockIoCallback_t;


/* Key-Socket API's */
int  KeySocket_Init(void);
int  KeySocket_CreateTcpSocket(KS_SOCKET_T* pSockfd);
int  KeySocket_CreateUdpSocket(KS_SOCKET_T* pSockfd);
int  KeySocket_SetIpMembership(KS_SOCKET_T sockFd, const struct in_addr* multiaddr, const struct in_addr* ifcaddr);
int  KeySocket_SetNonBlocking(KS_SOCKET_T sockFd);
int  KeySocket_Connect(KS_SOCKET_T sockfd, const struct in_addr* srvAddr, const unsigned short srvPort);
int  KeySocket_Select(KS_SOCKET_T sockFd, int timeoutMs);
int  KeySocket_Bind(KS_SOCKET_T sockFd, const struct in_addr* listenAddr, unsigned short listenPort);
int  KeySocket_Listen(KS_SOCKET_T sockFd, unsigned short listenPort, int listenMaxQueue);
int  KeySocket_Accept(KS_SOCKET_T sockFd, KS_SOCKET_T* pConnfd, int timeoutMs);
int  KeySocket_Recv(KS_SOCKET_T sockFd, char *buf, int sz, int flags);
int  KeySocket_Send(KS_SOCKET_T sockFd, const char *buf, int sz, int flags);
int  KeySocket_RecvFrom(KS_SOCKET_T sockFd, char *buf, int sz, int flags, struct sockaddr *addr, socklen_t *addrSz);
int  KeySocket_SendTo(KS_SOCKET_T sockFd, const char *buf, int sz, int flags, struct sockaddr *addr, socklen_t *addrSz);
void KeySocket_Close(KS_SOCKET_T* pSockfd);

int KeySocket_aton(const char *cp, struct in_addr *ap);


#endif /* _KEY_SOCKET_H_ */

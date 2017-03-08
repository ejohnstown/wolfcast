#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#ifndef NETX
    #include <arpa/inet.h>
    typedef struct SocketInfo_t {
        int txFd;
        int rxFd;
        struct sockaddr_in tx;
        unsigned int txSz;
    } SocketInfo_t;
#else
    #include "nx_api.h"
    #ifdef PGB000
        #include "pgb000_com.h"
    #else /* PGB002 */
        #include "pgb002_ap2.h"
    #endif

    typedef struct SocketInfo_t {
        NX_IP *ip;
        NX_PACKET_POOL *pool;
        NX_UDP_SOCKET txSocket;
        NX_UDP_SOCKET rxSocket;
        ULONG ipAddr;
        UINT port;
    } SocketInfo_t;
#endif

int WolfcastInit(int, unsigned short, const unsigned short *, unsigned int,
                 WOLFSSL_CTX **, WOLFSSL **, SocketInfo_t *);
int WolfcastClientInit(unsigned int *, unsigned int *);
int WolfcastClient(WOLFSSL *, unsigned short, unsigned int *, unsigned int *);
int WolfcastServer(WOLFSSL *);

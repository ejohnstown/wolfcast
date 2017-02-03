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
    typedef struct SocketInfo_t {
        NX_IP *ip_ptr;
        NX_UDP_SOCKET *txSocket;
        NX_UDP_SOCKET *rxSocket;
        ULONG ipAddr;
        UINT port;
    } SocketInfo_t;
#endif

int WolfcastInit(int, unsigned short, unsigned short *, unsigned int,
                 WOLFSSL_CTX **, WOLFSSL **, SocketInfo_t *);
int WolfcastClientInit(unsigned int *, unsigned int *);
int WolfcastClient(WOLFSSL *, unsigned short, unsigned int *, unsigned int *);
int WolfcastServer(WOLFSSL *);

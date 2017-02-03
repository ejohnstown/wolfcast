/* wolfcast.c */

/*
 gcc -Wall wolfcast.c -o ./wolfcast -lwolfssl

 run different clients on different hosts to see client sends,
 this is because we're disabling MULTICAST_LOOP so that we don't have to
 process messages we send ourselves

 could run ./wolfcast server on host 1 (this sends out a time msg every second)
 then run  ./wolfcast client on host 1 (will see server time msgs)
 then      ./wolfcast client on host 2 (will see server and client 1msgs, and
                                         host1 will see host2 msgs as well)
 
 $ ./wolfcast client <myId> <peerIdList>
 $ ./wolfcast server <myId>

 */


#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/memory.h>
#include "wolfcast.h"


#ifndef NETX

    #include <stdlib.h>
    #include <stdio.h>
    #include <errno.h>
    #include <string.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <time.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <fcntl.h>

    static unsigned int WCTIME(void)
    {
        return (unsigned int)time(NULL);
    }

    #define WCPRINTF printf

    static void WCERR(const char *msg)
    {
        if (msg != NULL)
            fprintf(stderr, "error: %s\n", msg);
    }

    #define GROUP_ADDR "226.0.0.3"
    #define GROUP_PORT 12345


    typedef struct SocketInfo_t {
        int txFd;
        int rxFd;
        struct sockaddr_in tx;
        unsigned int txSz;
        CallbackIOSend txCb;
        CallbackIORecv rxCb;
    } SocketInfo_t;


static int
CreateSockets(SocketInfo_t* si, int isClient)
{
    int error = 0, on = 1, off = 0;

    if (si != NULL) {

        /* Set to NULL for default callbacks. */
        si->txCb = NULL;
        si->rxCb = NULL;

        si->tx.sin_family = AF_INET;
        si->tx.sin_addr.s_addr = inet_addr(GROUP_ADDR);
        si->tx.sin_port = htons(GROUP_PORT);
        si->txSz = sizeof(si->tx);

        si->txFd = socket(AF_INET, SOCK_DGRAM, 0);
        if (si->txFd < 0) {
            error = 1;
            WCERR("unable to create tx socket");
        }

        if (!error) {
            if (setsockopt(si->txFd, SOL_SOCKET, SO_REUSEADDR,
                           &on, sizeof(on)) != 0) {
                error = 1;
                WCERR("couldn't set tx reuse addr");
            }
        }
#ifdef SO_REUSEPORT
        if (!error) {
            if (setsockopt(si->txFd, SOL_SOCKET, SO_REUSEPORT,
                           &on, sizeof(on)) != 0) {
                error = 1;
                WCERR("couldn't set tx reuse port");
            }
        }
#endif
        if (!error && isClient) {
            /* don't send to self */
            if (setsockopt(si->txFd, IPPROTO_IP, IP_MULTICAST_LOOP,
                           &off, sizeof(off)) != 0) {
                error = 1;
                WCERR("couldn't disable multicast loopback");
            }
        }
    }
    else {
        error = 1;
        WCERR("no socket info");
    }

    if (!error && isClient) {
        struct sockaddr_in rxAddr;

        memset(&rxAddr, 0, sizeof(rxAddr));
        rxAddr.sin_family = AF_INET;
        rxAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        rxAddr.sin_port = htons(GROUP_PORT);

        si->rxFd = socket(AF_INET, SOCK_DGRAM, 0);
        if (si->rxFd < 0) {
            error = 1;
            WCERR("unable to create rx socket");
        }

        if (!error) {
            if (setsockopt(si->rxFd, SOL_SOCKET, SO_REUSEADDR,
                           &on, (unsigned int)sizeof(on)) != 0) {
                error = 1;
                WCERR("couldn't set rx reuse addr");
            }
        }
#ifdef SO_REUSEPORT
        if (!error) {
            if (setsockopt(si->rxFd, SOL_SOCKET, SO_REUSEPORT,
                           &on, (unsigned int)sizeof(on)) != 0) {
                error = 1;
                WCERR("couldn't set rx reuse port");
            }
        }
#endif
        if (!error) {
            if (bind(si->rxFd, (struct sockaddr*)&rxAddr, sizeof(rxAddr)) != 0) {
                error = 1;
                WCERR("rx bind failed");
            }
        }

        if (!error) {
            struct ip_mreq imreq;
            memset(&imreq, 0, sizeof(imreq));

            imreq.imr_multiaddr.s_addr = inet_addr(GROUP_ADDR);
            imreq.imr_interface.s_addr = htonl(INADDR_ANY);

            if (setsockopt(si->rxFd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                           (const void*)&imreq, sizeof(imreq)) != 0) {
                error = 1;
                WCERR("setsockopt mc add membership failed");
            }
        }

        if (!error) {
            if (fcntl(si->rxFd, F_SETFL, O_NONBLOCK) == -1) {
                error = 1;
                WCERR("set nonblock failed");
            }
        }
    }

    return error;
}

#else /* NETX */

    #include "nx_api.h"

    static unsigned int WCTIME(void)
    {
        return (unsigned int)bsp_fast_timer_uptime() / 1000000;
    }

    #define WCPRINTF bsp_debug_printf

    static void WCERR(const char *msg)
    {
        if (msg != NULL)
            bsp_debug_printf("error: %s\n", msg);
    }

    #define GROUP_ADDR 0xE2000003
    #define GROUP_PORT 12345

    typedef struct SocketInfo_t {
        NX_IP *ip_ptr;
        int txFd;
        int rxFd;
        unsigned int tx;
        unsigned int txSz;
        CallbackIOSend txCb;
        CallbackIORecv rxCb;
    } SocketInfo_t;


static int
NetxDtlsTxCallback(
    WOLFSSL *ssl,
    char *buf, int sz,
    void *ctx)
{
	return 0;
}


static int
NetxDtlsRxCallback(
    WOLFSSL *ssl,
    char *buf, int sz,
    void *ctx)
{
	return 0;
}


static int
CreateSockets(SocketInfo_t* si, int isClient)
{
    int error = 0, on = 1, off = 0;

    if (si != NULL) {

		/* Set the NetX callbacks. */
		si->txCb = NetxDtlsTxCallback;
		si->rxCb = NetxDtlsRxCallback;

        txAddr->sin_family = AF_INET;
        txAddr->sin_addr.s_addr = GROUP_ADDR;
        txAddr->sin_port = GROUP_PORT;

        *txFd = socket(AF_INET, SOCK_DGRAM, 0);
        if (*txFd < 0) {
            error = 1;
            WCERR("unable to create tx socket");
        }

        if (!error) {
            if (setsockopt(*txFd, SOL_SOCKET, SO_REUSEADDR,
                           &on, (unsigned int)sizeof(on)) != 0) {
                error = 1;
                WCERR("couldn't set tx reuse addr");
            }
        }

        if (!error) {
            if (setsockopt(*txFd, SOL_SOCKET, SO_REUSEPORT,
                           &on, (unsigned int)sizeof(on)) != 0) {
                error = 1;
                WCERR("couldn't set tx reuse port");
            }
        }

        if (!error && rxFd != NULL) {
            /* don't send to self */
            if (setsockopt(*txFd, IPPROTO_IP, IP_MULTICAST_LOOP,
                           &off, sizeof(off)) != 0) {
                error = 1;
                WCERR("couldn't disable multicast loopback");
            }
        }
    }
    else {
        error = 1;
		WCERR("no socket info");
    }

    if (!error && rxFd != NULL && rxIp != NULL) {

        if (rxAddr != NULL && rxAddrSz != 0) {
            memset(rxAddr, 0, rxAddrSz);
            rxAddr->sin_family = AF_INET;
            rxAddr->sin_addr.s_addr = inet_addr(rxIp);
            rxAddr->sin_port = htons(port);
        }
        else {
            error = 1;
            WCERR("trying to create rx addr without address");
        }

        if (!error) {
            *rxFd = socket(AF_INET, SOCK_DGRAM, 0);
            if (*rxFd < 0) {
                error = 1;
                WCERR("unable to create rx socket");
            }
        }

        if (!error) {
            if (setsockopt(*rxFd, SOL_SOCKET, SO_REUSEADDR,
                           &on, (unsigned int)sizeof(on)) != 0) {
                error = 1;
                WCERR("couldn't set rx reuse addr");
            }
        }
#ifdef SO_REUSEPORT
        if (!error) {
            if (setsockopt(*rxFd, SOL_SOCKET, SO_REUSEPORT,
                           &on, (unsigned int)sizeof(on)) != 0) {
                error = 1;
                WCERR("couldn't set rx reuse port");
            }
        }
#endif
        if (!error) {
            if (bind(*rxFd, (struct sockaddr*)rxAddr, rxAddrSz) != 0) {
                error = 1;
                WCERR("rx bind failed");
            }
        }

        if (!error) {
            struct ip_mreq imreq;
            memset(&imreq, 0, sizeof(imreq));

            imreq.imr_multiaddr.s_addr = inet_addr(txIp);
            imreq.imr_interface.s_addr = inet_addr(rxIp);

            if (setsockopt(*rxFd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                           (const void*)&imreq, sizeof(imreq)) != 0) {
                error = 1;
                WCERR("setsockopt mc add membership failed");
            }
        }

        if (!error) {
            if (fcntl(*rxFd, F_SETFL, O_NONBLOCK) == -1) {
                error = 1;
                WCERR("set nonblock failed");
            }
        }
    }

    return error;
}

#endif


/* Missing items:
 * inet_addr()
 * select()
 * AF_INET
 * htons()
 * struct sockaddr_in
 * socket()
 * SOCK_DGRAM
 * setsockopt
 * SO_REUSEADDR
 * IPPROTO_IP
 * IP_MULTICAST_LOOP
 * bind
 * IP_ADD_MEMBERSHIP
 * struct ip_mreq
 * fcntl()
 * O_NONBLOCK
 * struct timeval
 */


static int
SetFakeKey(WOLFSSL* ssl)
{
    unsigned char pms[512];
    unsigned char cr[32];
    unsigned char sr[32];
    const unsigned char suite[2] = {0, 0xFE};  /* WDM_WITH_NULL_SHA256 */
    int error;

    memset(pms, 0x23, sizeof(pms));
    memset(cr, 0xA5, sizeof(cr));
    memset(sr, 0x5A, sizeof(sr));

    error = SSL_SUCCESS != wolfSSL_set_secret(ssl, 1, pms, sizeof(pms),
                                              cr, sr, suite);
    if (error)
        WCERR("cannot set ssl secret error");

    return error;
}


static int seq_cb(word16 peerId, word32 maxSeq, word32 curSeq, void* ctx)
{
    char* ctxStr = (char*)ctx;

    WCPRINTF("Highwater Callback (%u:%u/%u): %s\n", peerId, curSeq, maxSeq,
          ctxStr != NULL ? ctxStr : "Forgot to set the callback context.");

    return 0;
}


#define MSG_SIZE 80


#ifdef WOLFSSL_STATIC_MEMORY
    unsigned char memory[80000];
    unsigned char memoryIO[34500];
#endif


#ifndef NO_WOLFCAST_CLIENT

int
WolfcastClient(
    unsigned short myId,
    const unsigned short* peerIdList,
    unsigned int peerIdListSz)
{
    int ret, error = 0;
    char seqHwCbCtx[] = "Callback context string.";
    SocketInfo_t si;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    unsigned int i;

    error = CreateSockets(&si, 1);
    if (error)
        WCERR("Couldn't create sockets");

    wolfSSL_Init();

#ifndef WOLFSSL_STATIC_MEMORY
    if (!error)
        ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
#else
    ctx = NULL;
    if (!error) {
        ret = wolfSSL_CTX_load_static_memory(
                &ctx, wolfDTLSv1_2_client_method_ex,
                memory, sizeof(memory), 0, 1);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("unable to load static memory and create ctx");
        }
    }

    if (!error) {
        /* load in a buffer for IO */
        ret = wolfSSL_CTX_load_static_memory(
                &ctx, NULL, memoryIO, sizeof(memoryIO),
                WOLFMEM_IO_POOL_FIXED | WOLFMEM_TRACK_STATS, 1);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("unable to load static IO memory and create ctx");
        }
    }
#endif
    if (ctx == NULL) {
        error = 1;
        WCERR("ctx new error");
    }

    if (!error) {
        if (si.txCb != NULL && si.rxCb != NULL) {
            wolfSSL_SetIOSend(ctx, si.txCb);
            wolfSSL_SetIORecv(ctx, si.rxCb);
        }

        ret = wolfSSL_CTX_mcast_set_member_id(ctx, myId);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("set mcast member id error");
        }
    }

    if (!error) {
        ret = wolfSSL_CTX_mcast_set_highwater_cb(ctx, 100, 10, 20, seq_cb);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("set mcast highwater cb error");
        }
    }

    if (!error) {
        ssl = wolfSSL_new(ctx);
        if (!ssl) {
            error = 1;
            WCERR("ssl new error");
        }
    }

    if (!error) {
        #if 0
        wolfSSL_SetIOWriteCtx(ssl, NULL);
        wolfSSL_SetIOReadCtx(ssl, NULL);
        #endif
        ret = wolfSSL_set_read_fd(ssl, si.rxFd);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("set ssl read fd error");
        }
    }

    if (!error) {
        ret = wolfSSL_set_write_fd(ssl, si.txFd);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("set ssl write fd error");
        }
    }

    if (!error) {
        ret = wolfSSL_dtls_set_peer(ssl, &si.tx, si.txSz);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("set ssl sender error");
        }
    }

    if (!error) {
        ret = wolfSSL_mcast_set_highwater_ctx(ssl, seqHwCbCtx);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("set highwater ctx error");
        }
    }

    if (!error) {
        for (i = 0; i < peerIdListSz; i++) {
            ret = wolfSSL_mcast_peer_add(ssl, peerIdList[i], 0);
            if (ret != SSL_SUCCESS) {
                error = 1;
                WCERR("mcast add peer error");
                break;
            }
        }
    }

    if (!error) {
        wolfSSL_set_using_nonblock(ssl, 1);
        error = SetFakeKey(ssl);
    }

    if (!error) {
        unsigned int txtime = WCTIME() + 3;
        i = 0;

        for (;;) {
            char msg[MSG_SIZE];
            fd_set readfds;
            struct timeval timeout = {0, 500000};
            unsigned short peerId;

            FD_ZERO(&readfds);
            FD_SET(si.rxFd, &readfds);
            ret = select(si.rxFd+1, &readfds, NULL, NULL, &timeout);
            if (ret < 0) WCERR("main select failed");

            if (FD_ISSET(si.rxFd, &readfds)) {
                ssize_t n = wolfSSL_mcast_read(ssl, &peerId, msg, MSG_SIZE);
                if (n < 0) {
                    n = wolfSSL_get_error(ssl, n);
                    if (n != SSL_ERROR_WANT_READ) {
                        error = 1;
                        WCERR(wolfSSL_ERR_reason_error_string(n));
                        break;
                    }
                }
                else
                    printf("got msg from peer %u %s\n", peerId, msg);
            }

            unsigned int rxtime = WCTIME();
            if (rxtime >= txtime) {
                sprintf(msg, "%u sending message %d", myId, i++);
                size_t msg_len = strlen(msg) + 1;
                int n = wolfSSL_write(ssl, msg, (unsigned int)msg_len);
                if (n < 0) {
                    error = 1;
                    n = wolfSSL_get_error(ssl, n);
                    WCERR(wolfSSL_ERR_reason_error_string(n));
                    break;
                }

                txtime = rxtime + 3;
            }
        }
    }

    return error;
}

#endif


#ifndef NO_WOLFCAST_SERVER

int
WolfcastServer(unsigned short myId,
    const unsigned short* ignore1,
    unsigned int ignore2)
{
    int error, ret;
    SocketInfo_t si;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;

    (void)ignore1;
    (void)ignore2;

    wolfSSL_Init();

    error = CreateSockets(&si, 0);
    if (error)
        WCERR("Couldn't create sockets");

#ifndef WOLFSSL_STATIC_MEMORY
    if (!error)
        ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method());
#else
    if (!error) {
        ctx = NULL;
        ret = wolfSSL_CTX_load_static_memory(
                &ctx, wolfDTLSv1_2_server_method_ex,
                memory, sizeof(memory), 0, 1);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("unable to load static memory and create ctx");
        }
    }

    if (!error) {
        /* load in a buffer for IO */
        ret = wolfSSL_CTX_load_static_memory(
                &ctx, NULL, memoryIO, sizeof(memoryIO),
                WOLFMEM_IO_POOL_FIXED | WOLFMEM_TRACK_STATS, 1);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("unable to load static IO memory and create ctx");
        }
    }
#endif
    if (ctx == NULL) {
        error = 1;
        WCERR("ctx new error");
    }

    if (!error) {
        ret = wolfSSL_CTX_mcast_set_member_id(ctx, myId);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("set mcast member id error");
        }
    }

    if (!error) {
        ssl = wolfSSL_new(ctx);
        if (!ssl) {
            error = 1;
            WCERR("ssl new error");
        }
    }

    if (!error) {
        #if 0
        wolfSSL_SetIOWriteCtx(ssl, NULL);
        wolfSSL_SetIOReadCtx(ssl, NULL);
        #endif
        ret = wolfSSL_set_write_fd(ssl, si.txFd);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("set ssl write fd error");
        }
    }

    if (!error) {
        ret = wolfSSL_dtls_set_peer(ssl, &si.tx, si.txSz);
        if (ret != SSL_SUCCESS) {
            error = 1;
            WCERR("set ssl sender error");
        }
    }

    if (!error)
        error = SetFakeKey(ssl);

    if (!error) {
        for (;;) {
            char msg[80];
            unsigned int t = WCTIME();
            sprintf(msg, "time is %us", t);
            WCPRINTF("sending msg = %s\n", msg);
            unsigned int msg_len = (unsigned int)strlen(msg) + 1;
            int n = wolfSSL_write(ssl, msg, msg_len);
            if (n < 0) {
                error = 1;
                n = wolfSSL_get_error(ssl, n);
                WCERR(wolfSSL_ERR_reason_error_string(n));
                break;
            }

            sleep(1);
        }
    }

    return error;
}

#endif


#ifndef NO_MAIN_DRIVER

#define PEER_ID_LIST_SZ 99

int
main(
    int argc,
    char** argv)
{
    int error = 0;
    int isClient = 0;
    unsigned short myId;
    unsigned short peerIdList[PEER_ID_LIST_SZ];
    unsigned int peerIdListSz;

    if (argc == 3 || argc == 4) {
        long n;

        if (strcmp("client", argv[1]) == 0)
            isClient = 1;
        else if (strcmp("server", argv[1]) != 0) {
            error = 1;
            WCERR("type must be either client or server");
        }

        if (!error) {
            if ((isClient && argc != 4) || (!isClient && argc != 3)) {
                error = 1;
                WCPRINTF("Usage: wolfcast client <id> <peer list>\n"
                         "       wolfcast server <id>\n");
            }
        }

        if (!error) {
            n = strtol(argv[2], NULL, 10);
            if (n >= 0 && n < 256)
                myId = n;
            else {
                error = 1;
                WCERR("id must be between 0 and 255, inclusive");
            }
        }

        if (!error && isClient) {
            char *str = argv[3];
            char *endptr = argv[3];
            
            peerIdListSz = 0;
            do {
                if (peerIdListSz == PEER_ID_LIST_SZ) {
                    error = 1;
                    WCERR("too many peer ids");
                    break;
                }

                n = strtol(str, &endptr, 10);
                if (n >= 0 && n < 256) {
                    peerIdList[peerIdListSz] = n;
                    peerIdListSz++;

                    if (*endptr == ':')
                        str = endptr + 1;
                }
                else {
                    error = 1;
                    WCERR("peer ids must be between 0 and 255, inclusive");
                    break;
                }
            }
            while (*endptr != '\0');
        }
    }
    else {
        error = 1;
        WCPRINTF("Usage: wolfcast client <id> <peer list>\n"
                 "       wolfcast server <id>\n");
    }

    if (!error) {
        if (isClient) {
#ifndef NO_WOLFCAST_CLIENT
            error = WolfcastClient(myId, peerIdList, peerIdListSz);
#else
            error = 1;
#endif
        }
        else {
#ifndef NO_WOLFCAST_SERVER
            error = WolfcastServer(myId, peerIdList, peerIdListSz);
#else
            error = 1;
#endif
        }
    }

    return error;
}

#endif /* NO_MAIN_DRIVER */

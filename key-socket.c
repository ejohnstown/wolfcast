#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "key-socket.h"

/* 0=None, 1=Errors, 2=Verbose, 3=Debug */
#define KEY_SOCKET_LOGGING_LEVEL   0

#ifdef HAVE_NETX
    static NX_IP *nxIp = NULL;
    static NX_PACKET_POOL *nxPool = NULL;
#endif

int KeySocket_Init(void)
{
#ifdef HAVE_NETX
    #ifdef PGB000
        nxIp = &bsp_ip_system_bus;
        nxPool = &bsp_pool_system_bus;
    #else /* PGB002 */
        nxIp = &bsp_ip_local_bus;
        nxPool = &bsp_pool_local_bus;
    #endif
#endif
    return 0;
}

int KeySocket_CreateTcpSocket(KS_SOCKET_T* pSockfd)
{
    int ret = 0;
#ifdef HAVE_NETX
    ret = nx_tcp_socket_create(nxIp, *pSockfd, (char*)"tcp_socket",
        NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, TCP_WINDOW_SIZE,
        NX_NULL, NX_NULL);
#else
    int opt = 1;

    /* create a stream socket using tcp,internet protocal IPv4, full-duplex stream */
    *pSockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*pSockfd < 0) {
        return -1;
    }

    setsockopt(*pSockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    return ret;
}

int KeySocket_CreateUdpSocket(KS_SOCKET_T* pSockfd)
{
    int ret = 0;
#ifdef HAVE_NETX
    ret = nx_udp_socket_create(nxIp, (NX_UDP_SOCKET*)(*pSockfd), (char*)"udp_socket",
        NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, TCP_WINDOW_SIZE);
#else
    int opt = 1;

    /* Setup the multicast socket */
    *pSockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (*pSockfd < 0) {
        return -1;
    }

    setsockopt(*pSockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(*pSockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
#endif

    return ret;
}

int KeySocket_SetIpMembership(KS_SOCKET_T sockFd,
        const struct in_addr* multiaddr, const struct in_addr* ifcaddr)
{
    int ret = 0;

#ifdef HAVE_NETX
    (void)sockFd;
    (void)ifcaddr;
    ret = nx_igmp_multicast_join(nxIp, multiaddr->s_addr);
    if (ret != NX_SUCCESS) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("nx_igmp_multicast_join Error %d\n", ret);
#endif
        return -1;
    }
#else
    struct ip_mreq imreq;

    /* Allow anyone to join multicast group */
    memset(&imreq, 0, sizeof(imreq));
    imreq.imr_multiaddr.s_addr = multiaddr->s_addr;
    imreq.imr_interface.s_addr = ifcaddr->s_addr;
    ret = setsockopt(sockFd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                     (const void*)&imreq, sizeof(imreq));
    if (ret < 0) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        perror("setsockopt mc add membership failed");
#endif
    }
#endif

    return ret;
}

int KeySocket_Connect(KS_SOCKET_T sockfd, const struct in_addr* srvAddr, const unsigned short srvPort)
{
    int ret;

#ifdef HAVE_NETX
    ret = nx_tcp_client_socket_connect(sockfd,
        srvAddr->s_addr,
        srvPort,
        NX_WAIT_FOREVER);
    if (ret != NX_SUCCESS) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("nx_tcp_client_socket_connect Error %d\n", ret);
#endif
        return -1;
    }
#else
    struct sockaddr_in servaddr;

    XMEMSET(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = srvAddr->s_addr;
    servaddr.sin_port = htons(srvPort);

    /* attempts to make a connection on a socket */
    ret = connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
    if (ret != 0) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("Connection Error %d\n", ret);
#endif
        return -1;
    }
#endif

    return ret;
}


int KeySocket_Bind(KS_SOCKET_T sockFd, const struct in_addr* listenAddr, unsigned short listenPort)
{
    int ret = 0;

#ifdef HAVE_NETX
    (void)sockFd;
    (void)listenAddr;
    (void)listenPort;
    /* NetX doesn't bind the socket to a port on the server side. You
     * just listen to the port. */
#else
    struct sockaddr_in servAddr;

    /* set up server address and port */
    XMEMSET(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_addr.s_addr = listenAddr->s_addr;
    servAddr.sin_port        = htons(listenPort);

    /* bind to a socket */
    ret = bind(sockFd, (struct sockaddr*)&servAddr, sizeof(servAddr));
    if (ret < 0) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("Fatal error: bind error %d\n", ret);
#endif
    }

#endif

    return ret;
}

int KeySocket_SetNonBlocking(KS_SOCKET_T sockFd)
{
    int ret = 0;

#ifdef HAVE_NETX
    (void)sockFd;
    /* Nonblocking set when using socket. */
#else
    /* setup RX socket as non-blocking */
    ret = fcntl(sockFd, F_SETFL, O_NONBLOCK);
#endif

    return ret;
}


int KeySocket_Listen(KS_SOCKET_T sockFd, unsigned short listenPort, int listenMaxQueue)
{
    int ret;

#ifdef HAVE_NETX
    ret = nx_tcp_server_socket_listen(nxIp, listenPort, sockFd, listenMaxQueue, NULL);
    if (ret != NX_SUCCESS) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("Fatal error: listen error %d\n", ret);
#endif
        return -1;
    }

#else
    /* listen to the socket */
    ret = listen(sockFd, listenMaxQueue);
    if (ret < 0) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("Fatal error: listen error %d\n", ret);
#endif
        return -1;
    }

#endif

    return ret;
}


int KeySocket_Select(KS_SOCKET_T sockFd, int timeoutMs)
{
    int ret = 0;

#ifdef HAVE_NETX
    (void)sockFd;
    (void)timeoutMs;
#else
    struct timeval tv;
    fd_set readfds;

    tv.tv_sec = 0;
    tv.tv_usec = timeoutMs*1000; /* 100 ms */

    FD_ZERO(&readfds);
    FD_SET(sockFd, &readfds);

    ret = select(sockFd+1, &readfds, NULL, NULL, &tv);
    if (ret >= 0) {
        if (FD_ISSET(sockFd, &readfds)) {
            ret = 1;
        }
    }
#endif

    if (ret < 0) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("Select error %d\n", ret);
#endif
    }

    return ret;
}


int KeySocket_Accept(KS_SOCKET_T sockFd, KS_SOCKET_T* pConnfd, int timeoutMs)
{
    int ret = 0;

#ifdef HAVE_NETX
    (void)timeoutMs;

    if (sockFd->nx_tcp_socket_state != NX_TCP_LISTEN_STATE) {
        nx_tcp_socket_disconnect(sockFd, NX_WAIT_FOREVER);
    }

    nx_tcp_server_socket_unaccept(sockFd);
    nx_tcp_server_socket_relisten(sockFd->nx_tcp_socket_ip_ptr,
        sockFd->nx_tcp_socket_port, sockFd);

    ret = nx_tcp_server_socket_accept(sockFd, NX_WAIT_FOREVER);
    if (ret != NX_SUCCESS) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("Fatal error: accept error\n");
#endif
        return -1;
    }
    *pConnfd = sockFd; /* use same socket for listen and connection */

#else
    struct sockaddr_in cliAddr;
    socklen_t cliLen;

    cliLen = sizeof(cliAddr);

    ret = KeySocket_Select(sockFd, timeoutMs);
    if (ret > 0) {
        *pConnfd = accept(sockFd, (struct sockaddr *)&cliAddr, &cliLen);
        if (*pConnfd < 0) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf("Fatal error: accept error\n");
#endif
            return -1;
        }
        else {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            char ipStr[20];
            printf("Connection from %s, port %d\n",
                   inet_ntop(AF_INET, &cliAddr.sin_addr, ipStr, sizeof(ipStr)),
                   ntohs(cliAddr.sin_port));
#endif
        }
    }

#endif

    return ret;
}

int KeySocket_Recv(KS_SOCKET_T sockFd, char *buf, int sz, int flags)
{
    int recvd = 0;
#ifdef HAVE_NETX
    int status;
    NX_PACKET* nxPacket = NULL;
    ULONG total, copied, left, nxOffset = 0;

    status = nx_tcp_socket_receive(sockFd, &nxPacket, (ULONG)flags);
    if (status != NX_SUCCESS) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("NetX Recv receive error\n");
#endif
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    if (nxPacket) {
        status = nx_packet_length_get(nxPacket, &total);
        if (status != NX_SUCCESS) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf("NetX Recv length get error\n");
#endif
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        left = total - nxOffset;
        status = nx_packet_data_extract_offset(nxPacket, nxOffset,
                                               buf, sz, &copied);
        if (status != NX_SUCCESS) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf("NetX Recv data extract offset error\n");
#endif
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        nxOffset += copied;
        recvd = copied;

        if (copied == left) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf("NetX Recv Drained packet\n");
#endif
            nx_packet_release(nxPacket);
            nxPacket = NULL;
            nxOffset = 0;
        }
    }

#else
    recvd = (int)recv(sockFd, buf, sz, flags);
    if (recvd < 0) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("IO Recv error\n");
#endif
        if (errno == SOCKET_EWOULDBLOCK || errno == SOCKET_EAGAIN) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf(" Would block\n");
#endif
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
        else if (errno == SOCKET_ECONNRESET) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf("Connection reset\n");
#endif
            return WOLFSSL_CBIO_ERR_CONN_RST;
        }
        else if (errno == SOCKET_EINTR) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf("Socket interrupted\n");
#endif
            return WOLFSSL_CBIO_ERR_ISR;
        }
        else if (errno == SOCKET_ECONNREFUSED) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf("Connection refused\n");
#endif
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
        else if (errno == SOCKET_ECONNABORTED) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf("Connection aborted\n");
#endif
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        else {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf("General error\n");
#endif
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (recvd == 0) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("Embed receive connection closed\n");
#endif
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
#endif

    return recvd;
}


int KeySocket_Send(KS_SOCKET_T sockFd, const char *buf, int sz, int flags)
{
    int sent = 0;

#ifdef HAVE_NETX
    NX_PACKET*      packet;
    int status;

    status = nx_packet_allocate(nxPool, &packet, NX_TCP_PACKET, (ULONG)flags);
    if (status != NX_SUCCESS) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("NetX Send packet alloc error\n");
#endif
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    status = nx_packet_data_append(packet, (char*)buf, sz, nxPool,
            (ULONG)flags);
    if (status != NX_SUCCESS) {
        nx_packet_release(packet);
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("NetX Send data append error\n");
#endif
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    status = nx_tcp_socket_send(sockFd, packet, (ULONG)flags);
    if (status != NX_SUCCESS) {
        nx_packet_release(packet);
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("NetX Send socket send error\n");
#endif
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

#else
    sent = (int)send(sockFd, buf, sz, flags);
    if (sent < 0) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
        printf("IO Send error\n");
#endif
        if (errno == SOCKET_EWOULDBLOCK || errno == SOCKET_EAGAIN) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf("Would Block\n");
#endif
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }
        else if (errno == SOCKET_ECONNRESET) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf("Connection reset\n");
#endif
            return WOLFSSL_CBIO_ERR_CONN_RST;
        }
        else if (errno == SOCKET_EINTR) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf("Socket interrupted\n");
#endif
            return WOLFSSL_CBIO_ERR_ISR;
        }
        else if (errno == SOCKET_EPIPE) {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf("Socket EPIPE\n");
#endif
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        else {
#if KEY_SOCKET_LOGGING_LEVEL >= 1
            printf("General error\n");
#endif
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

#endif

    return sent;
}


void KeySocket_Close(KS_SOCKET_T* pSockfd)
{
    if (*pSockfd != KS_SOCKET_T_INIT) {
#ifdef HAVE_NETX
        nx_tcp_socket_delete(*pSockfd);
#else
        close(*pSockfd);
#endif
        *pSockfd = KS_SOCKET_T_INIT;
    }
}

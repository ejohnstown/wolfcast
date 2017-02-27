#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "key-services.h"

/* 0=None, 1=Errors, 2=Verbose, 3=Debug */
#define KEY_SERVICE_LOGGING_LEVEL   0

#define KEY_SERVICE_FORCE_CLIENT_TO_USE_NET /* for testing */


/*----------------------------------------------------------------------------*/
/* Server */
/*----------------------------------------------------------------------------*/

/* Generic responses for all supported packet types */
static CmdRespPacket_t* gRespPkt;
static int gKeyServerInitDone = 0;
static int gKeyServerRunning = 0;
static int gKeyServerStop = 0;

/*
 * Identify which psk key to use.
 */
static unsigned int KeyServer_PskCb(WOLFSSL* ssl, const char* identity,
    unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;

    if (XSTRNCMP(identity, CLIENT_IDENTITY, XSTRLEN(CLIENT_IDENTITY)) != 0) {
        return 0;
    }

    if (key_max_len > sizeof(g_TlsPsk)) {
        key_max_len = sizeof(g_TlsPsk);
    }
    XMEMCPY(key, g_TlsPsk, key_max_len);

    return key_max_len;
}


static int KeyServer_RecvCb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    KS_SOCKET_T sd = *(KS_SOCKET_T*)ctx;
    int flags = 0;
    int recvd;

    (void)ssl;

#ifdef NETX
    flags = NX_WAIT_FOREVER;
#endif
    recvd = KeySocket_Recv(sd, buf, sz, flags);

#if KEY_SERVICE_LOGGING_LEVEL >= 3
    printf("Received %d bytes\n", recvd);
#endif

    return recvd;
}

static int KeyServer_SendCb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    KS_SOCKET_T sd = *(KS_SOCKET_T*)ctx;
    int flags = 0;
    int sent;

    (void)ssl;

#ifdef NETX
    flags = NX_WAIT_FOREVER;
#endif
    sent = KeySocket_Send(sd, buf, sz, flags);

#if KEY_SERVICE_LOGGING_LEVEL >= 3
    printf("Sent %d bytes\n", sz);
#endif

    return sent;
}

static int KeyReq_Build(void* heap)
{
    int ret;
    WC_RNG rng;
    const int type = CMD_PKT_TYPE_KEY_REQ;

    /* get random data for key */
    ret = wc_InitRng_ex(&rng, heap);
    if (ret == 0) {
        CmdRespPacket_t* resp = &gRespPkt[type-1];

        ret = wc_RNG_GenerateBlock(&rng, resp->msg, MAX_PACKET_MSG);
        if (ret == 0) {
            /* populate generic response packet */
            resp->header.version = CMD_PKT_VERSION;
            resp->header.type = CMD_PKT_TYPE_KEY_REQ;
            resp->header.size = MAX_PACKET_MSG;
        }

        wc_FreeRng(&rng);
    }

    return ret;
}

static void KeyReq_GetResp(int type, unsigned char** resp, int* respLen)
{
    /* calculate and return packet size */
    if (respLen)
        *respLen = gRespPkt[type-1].header.size + sizeof(CmdPacketHeader_t);

    /* return buffer to response */
    if (resp)
        *resp = (unsigned char*)&gRespPkt[type-1];
}

static int KeyReq_Check(CmdReqPacket_t* reqPkt)
{
    int ret = 0;

    if (reqPkt == NULL) {
        return BAD_FUNC_ARG;
    }

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    printf("Request: Version %d, Cmd %d, Size %d\n",
        reqPkt->header.version, reqPkt->header.type, reqPkt->header.size);
#endif

    /* verify command version */
    if (reqPkt->header.version != CMD_PKT_VERSION) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyReq_Check: Invalid request version\n");
    #endif
        return -1;
    }

    /* verify command type */
    if (reqPkt->header.type >= CMD_PKT_TYPE_COUNT) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyReq_Check: Invalid request type\n");
    #endif
        return -1;
    }

    return ret;
}

/*
 * Handles request / response to client.
 */
static int KeyServer_Perform(WOLFSSL* ssl)
{
    int ret = 0;
    CmdReqPacket_t reqPkt;
    unsigned char* req = (unsigned char*)&reqPkt;
    unsigned char* resp;
    int n;

    XMEMSET(req, 0, sizeof(CmdReqPacket_t));
    n = wolfSSL_read(ssl, req, sizeof(CmdReqPacket_t));
    if (n > 0) {
        /* check request */
        ret = KeyReq_Check(&reqPkt);
        if (ret != 0) {
            return ret;
        }

        /* get response */
        KeyReq_GetResp(reqPkt.header.type, &resp, &n);

        /* write response */
        if (wolfSSL_write(ssl, resp, n) != n) {
            ret = wolfSSL_get_error(ssl, 0);
        #if KEY_SERVICE_LOGGING_LEVEL >= 1
            printf("KeyServer_Perform: write error %d\n", ret);
        #endif
            return ret;
        }
    }
    if (n < 0) {
        ret = wolfSSL_get_error(ssl, 0);
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyServer_Perform: read error %d\n", ret);
    #endif
        return ret;
    }

    return ret;
}



static int KeyServer_Init(void* heap)
{
    int ret = 0;

    if (gKeyServerInitDone == 0) {
        gRespPkt = (CmdRespPacket_t*)XMALLOC(
            sizeof(CmdRespPacket_t) * (CMD_PKT_TYPE_COUNT-1), heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (gRespPkt == NULL) {
            return MEMORY_E;
        }

        /* init each command type */
        ret = KeyReq_Build(heap);

        gKeyServerInitDone = 1;
    }

    return ret;
}

static void KeyServer_Free(void* heap)
{
    XFREE(gRespPkt, heap, DYNAMIC_TYPE_TMP_BUFFER);
}

int KeyServer_Run(void* heap)
{
    int                 ret = 0;
    KS_SOCKET_T listenfd = KS_SOCKET_T_INIT;
    KS_SOCKET_T connfd = KS_SOCKET_T_INIT;
    WOLFSSL_CTX*        ctx = NULL;
    WOLFSSL*            ssl = NULL;
    const unsigned long inAddrAny = INADDR_ANY;
#ifdef WOLFSSL_STATIC_MEMORY
    byte memory[80000];
    byte memoryIO[34500];
#endif
#ifdef NETX
    NX_TCP_SOCKET listensock;
    NX_TCP_SOCKET connsock;

    /* Extra lifting for NETX sockets */
    listenfd = &listensock;
    connfd = &connsock;
#endif

    /* generate response(s) */
    ret = KeyServer_Init(heap);
    if (ret != 0)
        goto exit;

    /* create and initialize WOLFSSL_CTX structure for TLS 1.2 only */
#ifndef WOLFSSL_STATIC_MEMORY
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
#else
    ret = wolfSSL_CTX_load_static_memory(
            &ctx, wolfTLSv1_2_server_method_ex,
            memory, sizeof(memory), 0, 1);
    if (ret != SSL_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("Error: unable to load static memory and create ctx\n");
    #endif
        goto exit;
    }

    /* load in a buffer for IO */
    ret = wolfSSL_CTX_load_static_memory(
            &ctx, NULL, memoryIO, sizeof(memoryIO),
            WOLFMEM_IO_POOL_FIXED | WOLFMEM_TRACK_STATS, 1);
    if (ret != SSL_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("Error: unable to load static IO memory and create ctx\n");
    #endif
        goto exit;
    }
#endif
    if (ctx == NULL) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("Error: wolfSSL_CTX_new error\n");
    #endif
        ret = MEMORY_E; goto exit;
    }

    /* set the IO callback methods */
    wolfSSL_SetIORecv(ctx, KeyServer_RecvCb);
    wolfSSL_SetIOSend(ctx, KeyServer_SendCb);

    /* use psk suite for security */
    wolfSSL_CTX_set_psk_server_callback(ctx, KeyServer_PskCb);
    wolfSSL_CTX_use_psk_identity_hint(ctx, SERVER_IDENTITY);
    if (wolfSSL_CTX_set_cipher_list(ctx, PSK_CIPHER_SUITE)
                                   != SSL_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("Error: server can't set cipher list\n");
    #endif
        ret = -1; goto exit;
    }

    /* create socket */
    ret = KeySocket_CreateTcpSocket(&listenfd);
    if (ret != 0) {
        goto exit;
    }

    /* setup socket listener */
    ret = KeySocket_Bind(listenfd, (const struct in_addr*)&inAddrAny, SERV_PORT);
    if (ret == 0) {
        ret = KeySocket_Listen(listenfd, SERV_PORT, LISTENQ);
    }
    if (ret != 0)
        goto exit;

    /* main loop for accepting and responding to clients */
    gKeyServerRunning = 1;
    while (gKeyServerStop == 0) {
        ret = KeySocket_Accept(listenfd, &connfd, 100);
        if (ret > 0) {
            /* create WOLFSSL object and respond */
            if ((ssl = wolfSSL_new(ctx)) == NULL) {
            #if KEY_SERVICE_LOGGING_LEVEL >= 1
                printf("Error: wolfSSL_new\n");
            #endif
                ret = MEMORY_E; goto exit;
            }

            /* set connection context */
        #ifdef HAVE_NETX
            wolfSSL_SetIO_NetX(ssl, connfd, NX_WAIT_FOREVER);
        #else
            ret = wolfSSL_set_fd(ssl, connfd);
            if (ret != SSL_SUCCESS)
                goto exit;
        #endif

            ret = KeyServer_Perform(ssl);
            if (ret != 0)
                goto exit;

            /* closes the connections after responding */
            wolfSSL_shutdown(ssl);
            wolfSSL_free(ssl); ssl = NULL;
            KeySocket_Close(&connfd);
        }
    }

exit:

    gKeyServerRunning = 0;

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    if (ret != 0) {
        printf("Key Server failure: %d\n", ret);
    }
#endif

    KeySocket_Close(&listenfd);
    KeySocket_Close(&connfd);

    /* free up memory used by wolfSSL */
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    KeyServer_Free(heap);

    return ret;
}

int KeyServer_IsRunning(void)
{
    return gKeyServerRunning;
}

void KeyServer_Stop(void)
{
    gKeyServerStop = 1;
}



/*----------------------------------------------------------------------------*/
/* Client */
/*----------------------------------------------------------------------------*/

/*
 *psk client set up.
 */
static inline unsigned int KeyClient_PskCb(WOLFSSL* ssl, const char* hint,
        char* identity, unsigned int id_max_len, unsigned char* key,
        unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;

    XSTRNCPY(identity, CLIENT_IDENTITY, id_max_len);

    if (key_max_len > sizeof(g_TlsPsk)) {
        key_max_len = sizeof(g_TlsPsk);
    }
    XMEMCPY(key, g_TlsPsk, key_max_len);

    return key_max_len;
}

static int KeyClient_RecvCb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    KS_SOCKET_T sd = *(KS_SOCKET_T*)ctx;
    int recvd;

    (void)ssl;

    recvd = KeySocket_Recv(sd, buf, sz, 0);

#if KEY_SERVICE_LOGGING_LEVEL >= 3
    printf("Received %d bytes\n", recvd);
#endif

    return recvd;
}


static int KeyClient_SendCb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    KS_SOCKET_T sd = *(KS_SOCKET_T*)ctx;
    int sent;

    (void)ssl;

    sent = KeySocket_Send(sd, buf, sz, 0);

#if KEY_SERVICE_LOGGING_LEVEL >= 3
    printf("Sent %d bytes\n", sz);
#endif

    return sent;
}

/*
 * Handles request / response from server.
 */
static int KeyClient_Perform(WOLFSSL* ssl, int type, unsigned char* msg, int* msgLen)
{
    int ret = 0, n;
    CmdReqPacket_t reqPkt;
    CmdRespPacket_t respPkt;
    unsigned char* req = (unsigned char*)&reqPkt;
    unsigned char* resp = (unsigned char*)&respPkt;

    XMEMSET(&reqPkt, 0, sizeof(reqPkt));
    reqPkt.header.version = CMD_PKT_VERSION;
    reqPkt.header.type = type;

    /* write request to the server */
    if (wolfSSL_write(ssl, req, sizeof(reqPkt)) != sizeof(reqPkt)) {
        ret = wolfSSL_get_error(ssl, 0);
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyClient_Perform: Write error %d to Server\n", ret);
    #endif
        return ret;
    }

    /* read response from server */
    if (wolfSSL_read(ssl, resp, sizeof(respPkt)) < 0 ) {
        ret = wolfSSL_get_error(ssl, 0);
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("KeyClient_Perform: Server terminate with error %d!\n", ret);
    #endif
        return ret;
    }

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    /* show response from the server */
    printf("Response: Version %d, Cmd %d, Size %d\n",
            respPkt.header.version, respPkt.header.type, respPkt.header.size);
#endif

    /* make sure resposne will fit into buffer */
    n = respPkt.header.size;
    if (n > *msgLen) {
        n = *msgLen;
    }

    /* return msg */
    XMEMCPY(msg, respPkt.msg, n);
    *msgLen = respPkt.header.size;

    return ret;
}


static int KeyClient_GetNet(const struct in_addr* srvAddr, int reqType,
    unsigned char* msg, int* msgLen, void* heap)
{
    int ret;
    KS_SOCKET_T sockfd = KS_SOCKET_T_INIT;
    WOLFSSL* ssl = NULL;
    WOLFSSL_CTX* ctx = NULL;
#ifdef WOLFSSL_STATIC_MEMORY
    byte memory[80000];
    byte memoryIO[34500];
#endif

    (void)heap;

    /* create and initialize WOLFSSL_CTX structure for TLS 1.2 only */
#ifndef WOLFSSL_STATIC_MEMORY
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
#else
    ret = wolfSSL_CTX_load_static_memory(
            &ctx, wolfTLSv1_2_client_method_ex,
            memory, sizeof(memory), 0, 1);
    if (ret != SSL_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("unable to load static memory and create ctx\n");
    #endif
        goto exit;
    }

    /* load in a buffer for IO */
    ret = wolfSSL_CTX_load_static_memory(
            &ctx, NULL, memoryIO, sizeof(memoryIO),
            WOLFMEM_IO_POOL_FIXED | WOLFMEM_TRACK_STATS, 1);
    if (ret != SSL_SUCCESS) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("unable to load static IO memory and create ctx\n");
    #endif
        goto exit;
    }
#endif
    if (ctx == NULL) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("wolfSSL_CTX_new error\n");
    #endif
        ret = MEMORY_E; goto exit;
    }

    /* set the IO callback methods */
    wolfSSL_SetIORecv(ctx, KeyClient_RecvCb);
    wolfSSL_SetIOSend(ctx, KeyClient_SendCb);

    /* set up pre shared keys */
    wolfSSL_CTX_set_psk_client_callback(ctx, KeyClient_PskCb);

    /* create socket */
    ret = KeySocket_CreateTcpSocket(&sockfd);
    if (ret != 0) {
        goto exit;
    }

    /* Connect to socket */
    ret = KeySocket_Connect(sockfd, srvAddr, SERV_PORT);
    if (ret != 0) {
        goto exit;
    }

    /* creat wolfssl object after each tcp connct */
    if ( (ssl = wolfSSL_new(ctx)) == NULL) {
    #if KEY_SERVICE_LOGGING_LEVEL >= 1
        printf("wolfSSL_new error\n");
    #endif
        ret = MEMORY_E; goto exit;
    }

    /* associate the file descriptor with the session */
#ifdef HAVE_NETX
    wolfSSL_SetIO_NetX(ssl, sockfd, NX_WAIT_FOREVER);
#else
    ret = wolfSSL_set_fd(ssl, sockfd);
    if (ret != SSL_SUCCESS)
        goto exit;

    wolfSSL_set_using_nonblock(ssl, 1);
#endif

    /* perform request and return response */
    ret = KeyClient_Perform(ssl, reqType, msg, msgLen);
    if (ret != 0)
        goto exit;

exit:

#if KEY_SERVICE_LOGGING_LEVEL >= 2
    if (ret != 0) {
        printf("Key Client failure: %d\n", ret);
    }
#endif

    KeySocket_Close(&sockfd);

    /* cleanup */
    wolfSSL_free(ssl);

    /* when completely done using SSL/TLS, free the
     * wolfssl_ctx object */
    wolfSSL_CTX_free(ctx);

    return ret;
}

#ifndef KEY_SERVICE_FORCE_CLIENT_TO_USE_NET
static int KeyClient_GetLocal(int reqType, unsigned char* msg, int* msgLen,
    void* heap)
{
    int ret;
    unsigned char* resp;
    int n;
    CmdReqPacket_t reqPkt;

    XMEMSET(&reqPkt, 0, sizeof(reqPkt));
    reqPkt.header.version = CMD_PKT_VERSION;
    reqPkt.header.type = reqType;

    /* check request */
    ret = KeyReq_Check(&reqPkt);
    if (ret != 0) {
        return ret;
    }

    KeyReq_GetResp(reqType, &resp, &n);

    /* return only length provided */
    if (n > *msgLen)
        n = *msgLen;

    memcpy(msg, resp, n);

    *msgLen = n;

    (void)heap;

    return ret;
}
#endif


int KeyClient_Get(const struct in_addr* srvAddr, int reqType, unsigned char* msg, int* msgLen, void* heap)
{
    int ret;

#ifndef KEY_SERVICE_FORCE_CLIENT_TO_USE_NET
    /* check to see if server is running locally */
    if (gKeyServerInitDone) {
        ret = KeyClient_GetLocal(reqType, msg, msgLen, heap);
    }
    else
#endif
    {
        ret = KeyClient_GetNet(srvAddr, reqType, msg, msgLen, heap);
    }

    return ret;
}

int KeyClient_GetKey(const struct in_addr* srvAddr, KeyRespPacket_t* keyResp, void* heap)
{
    int msgLen = sizeof(KeyRespPacket_t);
    return KeyClient_Get(srvAddr, CMD_PKT_TYPE_KEY_REQ, (unsigned char*)keyResp, &msgLen, heap);
}

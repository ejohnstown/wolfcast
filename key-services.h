#ifndef _KEY_SERVICE_H_
#define _KEY_SERVICE_H_

#include <stdint.h>
#include "key-socket.h"

#define PMS_SIZE       64 /* SHA256 Block size */
#define RAND_SIZE      32
#define MAX_PACKET_MSG (sizeof(KeyRespPacket_t))
#define SERV_PORT      11111  /* default port*/
#define LISTENQ        100*100   /* maximum backlog queue items */


#ifndef WOLFSSL_PACK
#if defined(__GNUC__)
    #define WOLFSSL_PACK __attribute__ ((packed))
#else
    #define WOLFSSL_PACK
#endif
#endif

/* Command Packet Version */
#define CMD_PKT_VERSION 0x01

/* Command Packet Types */
enum CmdPacketCommandType {
    CMD_PKT_TYPE_INVALID = 0,
    CMD_PKT_TYPE_KEY_REQ = 1,

    CMD_PKT_TYPE_COUNT,
};

/* Key Response Packet */
typedef struct KeyRespPacket {
    unsigned char pms[PMS_SIZE];
    unsigned char serverRandom[RAND_SIZE];
    unsigned char clientRandom[RAND_SIZE];
} WOLFSSL_PACK KeyRespPacket_t;

/* Command Header */
typedef struct CmdPacketHeader {
    unsigned char  version; /* Version = 1 - Allows future protocol changes */
    unsigned char  type;    /* Type: 1=KeyReq, 2=Future Commands */
    unsigned short size;    /* Message Size (remaining packet bytes to follow) */
} WOLFSSL_PACK CmdPacketHeader_t;

/* Command Request Packet */
typedef struct CmdReqPacket {
    struct CmdPacketHeader header;
} WOLFSSL_PACK CmdReqPacket_t;

/* Command Response Packet */
typedef struct CmdRespPacket {
    struct CmdPacketHeader header;
    union {
        unsigned char msg[MAX_PACKET_MSG];
        KeyRespPacket_t keyResp;
    };
} WOLFSSL_PACK CmdRespPacket_t;


/* PSK Client Identity */
/* Note: this is OpenSSL openssl s_client default, but can/should be customized */
#define CLIENT_IDENTITY  "Client_identity"

/* PSK Server Idenitity */
#define SERVER_IDENTITY  "wolfssl server"

/* PSK Cipher Suite */
#define PSK_CIPHER_SUITE "PSK-AES128-CBC-SHA256"

/* PSK - Shared Key */
static const unsigned char g_TlsPsk[64] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};


/* API's */
int KeyServer_Run(void* heap);
int KeyServer_IsRunning(void);
void KeyServer_Stop(void);

int KeyClient_Get(const struct in_addr* srvAddr, int reqType, unsigned char* msg, int* msgLen, void* heap);
int KeyClient_GetKey(const struct in_addr* srvAddr, KeyRespPacket_t* keyResp, void* heap);

#endif /* _KEY_SERVICE_H_ */

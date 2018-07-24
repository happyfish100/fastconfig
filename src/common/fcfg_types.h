#ifndef _FCFG_TYPES_H
#define _FCFG_TYPES_H

#include "fastcommon/common_define.h"

#define FCFG_SERVER_DEFAULT_INNER_PORT  20000
#define FCFG_SERVER_DEFAULT_OUTER_PORT  20000

#define FCFG_ERROR_INFO_SIZE             256

#define FCFG_CONFIG_STATUS_NORMAL        0
#define FCFG_CONFIG_STATUS_DELETED       1

#define FCFG_CONFIG_ENV_SIZE     65
#define FCFG_CONFIG_NAME_SIZE    65
#define FCFG_CONFIG_VALUE_SIZE   (64 * 1024)

typedef struct {
    unsigned char cmd;  //response command
    int body_len;       //response body length
} FCFGRequestInfo;

typedef struct {
    struct {
        char message[FCFG_ERROR_INFO_SIZE];
        int length;
    } error;
    int status;
    int body_len;    //response body length
    bool response_done;
    unsigned char cmd;   //response command
} FCFGResponseInfo;

typedef struct tagFCFGJoinResp {
    int64_t center_cfg_version;
} FCFGJoinResp;

typedef struct tagFCFGPushConfigHeader {
    short count;  //config count in body
} FCFGPushConfigHeader;

typedef struct tagFCFGPushConfigBodyPart {
    unsigned char status;
    unsigned char name_len;
    int value_len;
    int64_t version;
} FCFGPushConfigBodyPart;

#endif

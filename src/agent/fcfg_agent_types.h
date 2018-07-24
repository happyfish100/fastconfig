#ifndef _FCFG_AGENT_TYPES_H
#define _FCFG_AGENT_TYPES_H

#include "fastcommon/common_define.h"

typedef struct tagFCFGJoinResp {
    int64_t center_cfg_version;
} FCFGJoinResp;

typedef struct tagFCFGPushConfigHeader {
    short count;  //config count in body
} FCFGPushConfigHeader;

typedef struct tagFCFGPushConfigBodyPart {
    unsigned char status;
    unsigned char name_len;
    int value_len[4];
    int64_t version[8];
} FCFGPushConfigBodyPart;
#endif

#ifndef _FCFG_PROTO_H
#define _FCFG_PROTO_H

#include "fastcommon/fast_task_queue.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/connection_pool.h"
#include "fastcommon/ini_file_reader.h"
#include "fcfg_types.h"

#define FCFG_PROTO_ACTIVE_TEST_REQ    35   //center -> agent
#define FCFG_PROTO_ACTIVE_TEST_RESP   36

#define FCFG_PROTO_JION_REQ           37   //agent -> center
#define FCFG_PROTO_JION_RESP          38

#define FCFG_PROTO_PUSH_CONFIG        39   //center -> agent
#define FCFG_PROTO_PUSH_RESP          40

typedef struct fcfg_proto_header {
    char body_len[4];       //body length
    unsigned char cmd;      //the command code
    unsigned char status;   //status to store errno
    char padding[2];
} FCFGProtoHeader;

typedef struct fcfg_proto_join_req {
    char env[64];
    char agent_cfg_version[8];
} FCFGProtoJoinReq;

typedef struct fcfg_proto_join_resp {
    char center_cfg_version[8];
} FCFGProtoJoinResp;

typedef struct fcfg_proto_push_config_header {
    char count[2];  //config count in body
} FCFGProtoPushConfigHeader;

typedef struct fcfg_proto_push_config_body_part {
    unsigned char status;
    unsigned char name_len;
    char value_len[4];
    char version[8];
    char name[0];
    char *value;   //value = name + name_len
} FCFGProtoPushConfigBodyPart;

typedef struct fcfg_proto_push_resp {
    char agent_cfg_version[8];
} FCFGProtoPushResp;

#ifdef __cplusplus
extern "C" {
#endif

void fcfg_proto_init();

int fcfg_proto_set_body_length(struct fast_task_info *task);

int fcfg_proto_deal_actvie_test(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response);

static inline int fcfg_proto_expect_body_length(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response,
        const int expect_body_length, const char *filename, const int line)
{
    if (request->body_len != expect_body_length) {
        response->error.length = sprintf(response->error.message,
                "request body length: %d != %d",
                request->body_len, expect_body_length);

        logError("file: %s, line: %d, "
                "client ip: %s, cmd: %d, %s",
                filename, line, task->client_ip, request->cmd,
                response->error.message);
        return EINVAL;
    }

    return 0;
}

static inline int fcfg_proto_check_min_body_length(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response,
        const int min_body_length, const char *filename, const int line)
{
    if (request->body_len < min_body_length) {
        response->error.length = sprintf(response->error.message,
                "request body length: %d < %d",
                request->body_len, min_body_length);

        logError("file: %s, line: %d, "
                "client ip: %s, cmd: %d, %s",
                filename, line, task->client_ip, request->cmd,
                response->error.message);
        return EINVAL;
    }

    return 0;
}

#define FCFG_PROTO_EXPECT_BODY_LEN(task, request, response, expect_length) \
    fcfg_proto_expect_body_length(task, request, response, expect_length, __FILE__, __LINE__)

#define FCFG_PROTO_CHECK_MIN_BODY_LEN(task, request, response, min_length) \
    fcfg_proto_check_min_body_length(task, request, response, min_length, __FILE__, __LINE__)

#ifdef __cplusplus
}
#endif

#endif

#ifndef _FCFG_PROTO_H
#define _FCFG_PROTO_H

#include "fastcommon/fast_task_queue.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/connection_pool.h"
#include "fastcommon/ini_file_reader.h"
#include "fcfg_types.h"

#define FCFG_PROTO_ACK                  6

#define FCFG_PROTO_ACTIVE_TEST_REQ     36

typedef struct fcfg_proto_header {
    char body_len[4];       //body length
    unsigned char cmd;      //the command code
    unsigned char status;   //status to store errno
    char padding[2];
} FCFGProtoHeader;

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

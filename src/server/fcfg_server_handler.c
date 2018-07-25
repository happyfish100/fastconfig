//fcfg_server_handler.c

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "fastcommon/logger.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/ioevent_loop.h"
#include "sf/sf_util.h"
#include "sf/sf_func.h"
#include "sf/sf_nio.h"
#include "sf/sf_global.h"
#include "common/fcfg_proto.h"
#include "fcfg_server_types.h"
#include "fcfg_server_global.h"
#include "fcfg_server_func.h"
#include "fcfg_server_dao.h"
#include "fcfg_server_handler.h"

int fcfg_server_handler_init()
{
    return 0;
}

int fcfg_server_handler_destroy()
{   
    return 0;
}

void fcfg_server_task_finish_cleanup(struct fast_task_info *task)
{
    sf_task_finish_clean_up(task);
}

static int fcfg_proto_deal_join(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response)
{
    FCFGProtoAgentJoinReq *join_req;
    FCFGProtoAgentJoinResp *join_resp;
    char env[FCFG_CONFIG_ENV_SIZE];
    int result;
    int64_t agent_cfg_version;
    int64_t center_cfg_version = 0;  //TODO

    if ((result=FCFG_PROTO_EXPECT_BODY_LEN(task, request, response,
                    sizeof(FCFGProtoAgentJoinReq))) != 0)
    {
        return result;
    }

    memset(env, 0, sizeof(env));
    join_req = (FCFGProtoAgentJoinReq *)(task->data + sizeof(FCFGProtoHeader));
    memcpy(env, join_req->env, sizeof(join_req->env));
    if (!fcfg_server_env_exists(env)) {
        response->error.length = sprintf(response->error.message,
                "env: %s not exist", env);

        logError("file: "__FILE__", line: %d, "
                "client ip: %s, cmd: %d, %s",
                __LINE__, task->client_ip, request->cmd,
                response->error.message);
        return EINVAL;
    }

    agent_cfg_version = buff2long(join_req->agent_cfg_version);
    logInfo("agent_cfg_version: %"PRId64, agent_cfg_version);

    join_resp = (FCFGProtoAgentJoinResp *)(task->data + sizeof(FCFGProtoHeader));
    long2buff(center_cfg_version, join_resp->center_cfg_version);

    response->body_len = 8;
    response->cmd = FCFG_PROTO_AGENT_JOIN_RESP;
    response->response_done = true;
    return 0;
}

static int fcfg_proto_deal_add_del_env(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response)
{
    FCFGMySQLContext *mysql_context;
    char *env;
    int result;

    if ((result=FCFG_PROTO_CHECK_BODY_LEN(task, request, response,
                    1, FCFG_CONFIG_ENV_SIZE - 1)) != 0)
    {
        return result;
    }

    mysql_context = &((FCFGServerContext *)task->arg)->mysql_context;
    env = task->data + sizeof(FCFGProtoHeader);
    *(env + request->body_len) = '\0';
    if (request->cmd == FCFG_PROTO_ADD_ENV_REQ) {
        return fcfg_server_dao_add_env(mysql_context, env);
    } else {
        return fcfg_server_dao_del_env(mysql_context, env);
    }
}

int fcfg_server_deal_task(struct fast_task_info *task)
{
    FCFGProtoHeader *proto_header;
    FCFGRequestInfo request;
    FCFGResponseInfo response;
    int result;
    int r;
    int64_t tbegin;
    int time_used;

    tbegin = get_current_time_ms();
    response.cmd = FCFG_PROTO_ACK;
    response.body_len = 0;
    response.error.length = 0;
    response.error.message[0] = '\0';
    response.response_done = false;

    request.cmd = ((FCFGProtoHeader *)task->data)->cmd;
    request.body_len = task->length - sizeof(FCFGProtoHeader);
    do {
        switch (request.cmd) {
            case FCFG_PROTO_ACTIVE_TEST_REQ:
                response.cmd = FCFG_PROTO_ACTIVE_TEST_RESP;
                result = fcfg_proto_deal_actvie_test(task, &request, &response);
                break;
            case FCFG_PROTO_AGENT_JOIN_REQ:
                result = fcfg_proto_deal_join(task, &request, &response);
                break;
            case FCFG_PROTO_ADD_ENV_REQ:
                result = fcfg_proto_deal_add_del_env(task, &request, &response);
                break;
            case FCFG_PROTO_DEL_ENV_REQ:
                result = fcfg_proto_deal_add_del_env(task, &request, &response);
                break;
            default:
                response.error.length = sprintf(response.error.message,
                    "unkown cmd: %d", request.cmd);
                lerr("client ip: %s, unknow cmd: %d, body length: %d",
                        task->client_ip, request.cmd, request.body_len);
                result = -EINVAL;
                break;
        }
    } while(0);

    proto_header = (FCFGProtoHeader *)task->data;
    if (!response.response_done) {
        response.body_len = response.error.length;
        if (response.error.length > 0) {
            memcpy(task->data + sizeof(FCFGProtoHeader),
                    response.error.message, response.error.length);
        }
    }

    proto_header->status = result >= 0 ? result : -1 * result;
    proto_header->cmd = response.cmd;
    int2buff(response.body_len, proto_header->body_len);
    task->length = sizeof(FCFGProtoHeader) + response.body_len;

    r = sf_send_add_event(task);
    time_used = (int)(get_current_time_ms() - tbegin);
    if (time_used > 1000) {
        lwarning("timed used to process a request is %d ms, "
                "cmd: %d, req body len: %d, resp body len: %d",
                time_used, request.cmd,
                request.body_len, response.body_len);
    }

    ldebug("req cmd: %d, req body_len: %d, "
            "resp cmd: %d, status: %d, resp body_len: %d, "
            "time used: %d ms",
            request.cmd, request.body_len,
            response.cmd, proto_header->status,
            response.body_len, time_used);

    return r == 0 ? result : r;
}

void *fcfg_server_alloc_thread_extra_data(const int thread_index)
{
    FCFGServerContext *thread_extra_data;

    thread_extra_data = (FCFGServerContext *)malloc(sizeof(FCFGServerContext));
    if (thread_extra_data == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail, errno: %d, error info: %s",
                __LINE__, (int)sizeof(FCFGServerContext),
                errno, strerror(errno));
        return NULL;
    }

    memset(thread_extra_data, 0, sizeof(FCFGServerContext));
    fcfg_server_dao_init(&thread_extra_data->mysql_context);

    return thread_extra_data;
}

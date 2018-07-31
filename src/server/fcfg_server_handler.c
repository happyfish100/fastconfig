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
#include "fcfg_server_cfg.h"
#include "fcfg_server_push.h"
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
    FCFGServerTaskArg *task_arg;

    task_arg = (FCFGServerTaskArg *)task->arg;

    fcfg_server_cfg_remove_subscriber(task);
    task_arg->msg_queue.config_array = NULL;
    task_arg->msg_queue.agent_cfg_version = 0;
    task_arg->msg_queue.offset = 0;
    task_arg->waiting_type = FCFG_SERVER_TASK_WAITING_REQUEST;

    __sync_add_and_fetch(&((FCFGServerTaskArg *)task->arg)->task_version, 1);
    sf_task_finish_clean_up(task);

    logInfo("task_version: %"PRId64, ((FCFGServerTaskArg *)task->arg)->task_version);
}

int fcfg_server_recv_timeout_callback(struct fast_task_info *task)
{
    FCFGServerTaskArg *task_arg;
    task_arg = (FCFGServerTaskArg *)task->arg;
    if ((task_arg->waiting_type & FCFG_SERVER_TASK_WAITING_RESP) != 0) {
        logWarning("file: "__FILE__", line: %d, "
                "client ip: %s, waiting type: %d, "
                "recv timeout", __LINE__, task->client_ip,
                task_arg->waiting_type);
        return ETIMEDOUT;
    }

    if (g_current_time - task_arg->last_recv_pkg_time >=
            g_server_global_vars.check_alive_interval)
    {
        return fcfg_server_add_task_event(task, FCFG_SERVER_EVENT_TYPE_ACTIVE_TEST);
    }

    return 0;
}

static int fcfg_proto_deal_join(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response)
{
    FCFGProtoAgentJoinReq *join_req;
    FCFGProtoAgentJoinResp *join_resp;
    char env[FCFG_CONFIG_ENV_SIZE];
    int result;
    int64_t agent_cfg_version;
    int64_t center_cfg_version;

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

    if ((result=fcfg_server_cfg_add_subscriber(env, task)) != 0) {
        return result;
    }

    agent_cfg_version = buff2long(join_req->agent_cfg_version);
    center_cfg_version = ((FCFGServerTaskArg *)task->arg)->publisher->current_version;
    if (agent_cfg_version > center_cfg_version) {
        logWarning("file: "__FILE__", line: %d, client ip: %s, "
                "agent_cfg_version: %"PRId64" > center_cfg_version: %"PRId64,
                __LINE__, task->client_ip, agent_cfg_version, center_cfg_version);
    } else if (agent_cfg_version < center_cfg_version) {
        result = fcfg_server_add_config_push_event(task);
    }

    logInfo("file: "__FILE__", line: %d, client ip: %s, "
            "agent_cfg_version: %"PRId64", center_cfg_version: %"PRId64,
            __LINE__, task->client_ip, agent_cfg_version, center_cfg_version);

    ((FCFGServerTaskArg *)task->arg)->msg_queue.agent_cfg_version = agent_cfg_version;
    join_resp = (FCFGProtoAgentJoinResp *)(task->data + sizeof(FCFGProtoHeader));
    long2buff(center_cfg_version, join_resp->center_cfg_version);

    response->body_len = 8;
    response->cmd = FCFG_PROTO_AGENT_JOIN_RESP;
    response->response_done = true;
    return result;
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

    mysql_context = &((FCFGServerContext *)task->thread_data->arg)->mysql_context;
    env = task->data + sizeof(FCFGProtoHeader);
    *(env + request->body_len) = '\0';
    if (request->cmd == FCFG_PROTO_ADD_ENV_REQ) {
        return fcfg_server_dao_add_env(mysql_context, env);
    } else {
        return fcfg_server_dao_del_env(mysql_context, env);
    }
}

static int fcfg_proto_deal_push_config_resp(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response)
{
    int result;
    FCFGProtoPushResp *push_resp;
    int64_t agent_cfg_version;
    FCFGServerTaskArg *task_arg;

    if ((result=FCFG_PROTO_EXPECT_BODY_LEN(task, request, response,
                    sizeof(FCFGProtoPushResp))) != 0)
    {
        return result;
    }

    task_arg = (FCFGServerTaskArg *)task->arg;
    push_resp = (FCFGProtoPushResp *)(task->data + sizeof(FCFGProtoHeader));
    agent_cfg_version = buff2long(push_resp->agent_cfg_version);
    if (agent_cfg_version != task_arg->msg_queue.agent_cfg_version) {
        logError("file: "__FILE__", line: %d, client ip: %s, "
                "response agent_cfg_version: %"PRId64" != %"
                PRId64, __LINE__, task->client_ip, agent_cfg_version,
                task_arg->msg_queue.agent_cfg_version);
        return EINVAL;
    }

    return fcfg_server_push_configs(task);
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
    int expect_waiting_type;

    tbegin = get_current_time_ms();
    response.cmd = FCFG_PROTO_ACK;
    response.body_len = 0;
    response.error.length = 0;
    response.error.message[0] = '\0';
    response.response_done = false;

    ((FCFGServerTaskArg *)task->arg)->last_recv_pkg_time = g_current_time;
    request.cmd = ((FCFGProtoHeader *)task->data)->cmd;
    request.body_len = task->length - sizeof(FCFGProtoHeader);
    do {
        switch (request.cmd) {
            case FCFG_PROTO_ACTIVE_TEST_REQ:
                response.cmd = FCFG_PROTO_ACTIVE_TEST_RESP;
                result = fcfg_proto_deal_actvie_test(task, &request, &response);
                break;
            case FCFG_PROTO_PUSH_RESP:
            case FCFG_PROTO_ACTIVE_TEST_RESP:
                if (request.cmd == FCFG_PROTO_PUSH_RESP) {
                    expect_waiting_type = FCFG_SERVER_TASK_WAITING_PUSH_RESP;
                } else {
                    expect_waiting_type = FCFG_SERVER_TASK_WAITING_ACTIVE_TEST_RESP;
                }
                if ((((FCFGServerTaskArg *)task->arg)->waiting_type &
                            expect_waiting_type) == 0)
                {
                    lerr("client ip: %s, unknow expect cmd: %d, body length: %d",
                            task->client_ip, request.cmd, request.body_len);
                    return -EINVAL;
                }

                ((FCFGServerTaskArg *)task->arg)->waiting_type &= ~expect_waiting_type;
                if (request.cmd == FCFG_PROTO_PUSH_RESP) {
                    result = fcfg_proto_deal_push_config_resp(task, &request, &response);
                } else {
                    result = 0;
                }

                task->offset = task->length = 0;
                return result > 0 ? -1 * result : result;
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
    common_blocked_queue_init_ex(&thread_extra_data->push_queue, 4096);
    return thread_extra_data;
}

static int fcfg_server_send_active_test(struct fast_task_info *task)
{
    FCFGProtoHeader *proto_header;

    logInfo("file: "__FILE__", line: %d, "
            "client ip: %s, send_active_test",
            __LINE__, task->client_ip);

    task->length = sizeof(FCFGProtoHeader);
    proto_header = (FCFGProtoHeader *)task->data;
    int2buff(0, proto_header->body_len);
    proto_header->cmd = FCFG_PROTO_ACTIVE_TEST_REQ;
    proto_header->status = 0;
    ((FCFGServerTaskArg *)task->arg)->waiting_type |=
        FCFG_SERVER_TASK_WAITING_ACTIVE_TEST_RESP;
    return sf_send_add_event(task);
}

int fcfg_server_thread_loop(struct nio_thread_data *thread_data)
{
    struct common_blocked_queue *push_queue;
    FCFGServerPushEvent *event;
    FCFGServerTaskArg *task_arg;
    int64_t task_version;
    int unexpect_waiting_type;

    push_queue = &((FCFGServerContext *)thread_data->arg)->push_queue;

    while ((event=(FCFGServerPushEvent *)common_blocked_queue_try_pop(
                    push_queue)) != NULL)
    {
        task_arg = (FCFGServerTaskArg *)event->task->arg;

        task_version = __sync_add_and_fetch(&task_arg->task_version, 0);
        if (event->task_version != task_version) {
            logInfo("file: "__FILE__", line: %d, client ip: %s, "
                    "task version changed, current task version: %"PRId64", "
                    "task version in event: %"PRId64, __LINE__,
                    event->task->client_ip, task_version, event->task_version);
            fcfg_server_free_event(event);
            continue;
        }

        if (event->type == FCFG_SERVER_EVENT_TYPE_PUSH_CONFIG) {
            unexpect_waiting_type = FCFG_SERVER_TASK_WAITING_PUSH_RESP;
        } else {
            unexpect_waiting_type = FCFG_SERVER_TASK_WAITING_ACTIVE_TEST_RESP;
        }
        if ((sf_client_sock_in_read_stage(event->task) && event->task->offset == 0) &&
                (task_arg->waiting_type & unexpect_waiting_type) == 0)
        {
            if (event->type == FCFG_SERVER_EVENT_TYPE_PUSH_CONFIG) {
                fcfg_server_push_configs(event->task);
            } else {
                fcfg_server_send_active_test(event->task);
            }
        }

        fcfg_server_free_event(event);
    }

    return 0;
}

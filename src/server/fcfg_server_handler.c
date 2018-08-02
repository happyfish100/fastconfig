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
    task_arg->joined = false;

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

static int fcfg_proto_deal_agent_join(struct fast_task_info *task,
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

    ((FCFGServerTaskArg *)task->arg)->joined = true;
    response->body_len = 8;
    response->cmd = FCFG_PROTO_AGENT_JOIN_RESP;
    response->response_done = true;
    return result;
}

static int fcfg_proto_deal_admin_join(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response)
{
    FCFGProtoAdminJoinReq *join_req;
    string_t username;
    string_t secret_key;
    int expect_len;
    int result;

    if ((result=FCFG_PROTO_CHECK_BODY_LEN(task, request, response,
                    sizeof(FCFGProtoAdminJoinReq), 256)) != 0)
    {
        return result;
    }

    join_req = (FCFGProtoAdminJoinReq *)(task->data + sizeof(FCFGProtoHeader));
    username.len = join_req->username_len;
    secret_key.len = join_req->secret_key_len;
    username.str = join_req->username;
    secret_key.str = join_req->username + username.len;

    expect_len = sizeof(FCFGProtoAdminJoinReq) + username.len + secret_key.len;
    if (request->body_len != expect_len) {
        response->error.length = sprintf(response->error.message,
                "invalid body length: %d,  expect length: %d",
                request->body_len, expect_len);
        logError("file: "__FILE__", line: %d, "
                "client ip: %s, cmd: %d, %s",
                __LINE__, task->client_ip, request->cmd,
                response->error.message);
        return EINVAL;
    }

    if (!(fc_compare_string(&username, &g_server_global_vars.admin.username) == 0 &&
            fc_compare_string(&secret_key, &g_server_global_vars.admin.secret_key) == 0))
    {
        response->error.length = sprintf(response->error.message,
                "invalid username or secret_key");

        logError("file: "__FILE__", line: %d, "
                "client ip: %s, cmd: %d, %s. "
                "username: %.*s, secret_key: %.*s",
                __LINE__, task->client_ip, request->cmd,
                response->error.message, username.len, username.str,
                secret_key.len, secret_key.str);
        return EINVAL;
    }

    ((FCFGServerTaskArg *)task->arg)->joined = true;
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

static int fcfg_proto_deal_get_env(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response)
{
    FCFGMySQLContext *mysql_context;
    FCFGProtoGetEnvResp *env_resp;
    FCFGEnvEntry entry;
    char env[FCFG_CONFIG_ENV_SIZE];
    int result;

    if ((result=FCFG_PROTO_CHECK_BODY_LEN(task, request, response,
                    1, FCFG_CONFIG_ENV_SIZE - 1)) != 0)
    {
        return result;
    }

    mysql_context = &((FCFGServerContext *)task->thread_data->arg)->mysql_context;
    memcpy(env, task->data + sizeof(FCFGProtoHeader), request->body_len);
    *(env + request->body_len) = '\0';
    if ((result=fcfg_server_dao_get_env(mysql_context, env, &entry)) != 0) {
        return result;
    }

    env_resp = (FCFGProtoGetEnvResp *)(task->data + sizeof(FCFGProtoHeader));
    env_resp->env_len = entry.env.len;
    int2buff(entry.create_time, env_resp->create_time);
    int2buff(entry.update_time, env_resp->update_time);
    memcpy(env_resp->env, entry.env.str, entry.env.len);

    response->body_len = sizeof(FCFGProtoGetEnvResp) + entry.env.len;
    response->cmd = FCFG_PROTO_GET_ENV_RESP;
    response->response_done = true;
    return 0;
}

static int fcfg_proto_deal_list_env(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response)
{
    FCFGMySQLContext *mysql_context;
    FCFGProtoListEnvRespHeader *resp_header;
    FCFGProtoGetEnvResp *env_resp;
    char *p;
    FCFGEnvEntry *entry;
    FCFGEnvEntry *end;
    FCFGEnvArray array;
    int result;
    int expect_size;

    if ((result=FCFG_PROTO_EXPECT_BODY_LEN(task, request, response, 0)) != 0) {
        return result;
    }

    mysql_context = &((FCFGServerContext *)task->thread_data->arg)->mysql_context;
    if ((result=fcfg_server_dao_list_env(mysql_context, &array)) != 0) {
        return result;
    }

    end = array.rows + array.count;
    expect_size = sizeof(FCFGProtoHeader) + sizeof(FCFGProtoListEnvRespHeader);
    for (entry=array.rows; entry<end; entry++) {
        expect_size += sizeof(FCFGProtoGetEnvResp) + entry->env.len;
    }
    if (expect_size > task->size) {
        if ((result=free_queue_set_buffer_size(task, expect_size)) != 0) {
            fcfg_server_dao_free_env_array(&array);
            return result;
        }
    }

    p = task->data + sizeof(FCFGProtoHeader) + sizeof(FCFGProtoListEnvRespHeader);
    for (entry=array.rows; entry<end; entry++) {
        env_resp = (FCFGProtoGetEnvResp *)p;
        env_resp->env_len = entry->env.len;
        int2buff(entry->create_time, env_resp->create_time);
        int2buff(entry->update_time, env_resp->update_time);
        memcpy(env_resp->env, entry->env.str, entry->env.len);
        
        p += sizeof(FCFGProtoGetEnvResp) + entry->env.len;
    }

    resp_header = (FCFGProtoListEnvRespHeader *)(task->data + sizeof(FCFGProtoHeader));
    short2buff(array.count, resp_header->count);
    response->body_len = (p - task->data) - sizeof(FCFGProtoHeader);
    response->cmd = FCFG_PROTO_LIST_ENV_RESP;
    response->response_done = true;

    fcfg_server_dao_free_env_array(&array);
    return 0;
}

static int fcfg_proto_deal_set_config(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response)
{
    FCFGMySQLContext *mysql_context;
    FCFGProtoSetConfigReq *set_config_req;
    char env[FCFG_CONFIG_ENV_SIZE];
    char name[FCFG_CONFIG_NAME_SIZE];
    int env_len;
    int name_len;
    int data_body_len;
    string_t value;
    int result;

    if ((result=FCFG_PROTO_CHECK_BODY_LEN(task, request, response,
                    sizeof(FCFGProtoSetConfigReq),
                    sizeof(FCFGProtoSetConfigReq) + FCFG_CONFIG_MAX_ENV_LEN +
                    FCFG_CONFIG_MAX_NAME_LEN + FCFG_CONFIG_MAX_VALUE_LEN)) != 0)
    {
        return result;
    }

    set_config_req = (FCFGProtoSetConfigReq *)(task->data + sizeof(FCFGProtoHeader));

    env_len = set_config_req->env_len;
    name_len = set_config_req->name_len;
    value.len = buff2int(set_config_req->value_len);

    do {
        if (env_len <= 0 || env_len > FCFG_CONFIG_MAX_ENV_LEN) {
            response->error.length = sprintf(response->error.message,
                    "invalid env length: %d", env_len);
            result = EINVAL;
            break;
        }

        if (name_len <= 0 || name_len  > FCFG_CONFIG_MAX_NAME_LEN) {
            response->error.length = sprintf(response->error.message,
                    "invalid name length: %d", name_len);
            result = EINVAL;
            break;
        }

        if (value.len < 0 || value.len > FCFG_CONFIG_MAX_VALUE_LEN) {
            response->error.length = sprintf(response->error.message,
                    "invalid value length: %d", value.len);
            result = EINVAL;
            break;
        }

        data_body_len = sizeof(FCFGProtoSetConfigReq) +
            env_len + name_len + value.len;
        if (request->body_len != data_body_len) {
            response->error.length = sprintf(response->error.message,
                    "invalid body length: %d, expect: %d",
                    request->body_len, data_body_len);
            result = EINVAL;
            break;
        }

 
        memcpy(env, set_config_req->env, env_len);
        *(env + env_len) = '\0';
        if (!fcfg_server_env_exists(env)) {
            response->error.length = sprintf(response->error.message,
                    "env: %s not exist", env);
            result = ENOENT;
            break;
        }

        memcpy(name, set_config_req->env + env_len, name_len);
        *(name + name_len) = '\0';

        value.str = set_config_req->env + env_len + name_len;
        *(value.str + value.len) = '\0';

    } while (0);

    if (result != 0) {
        logError("file: "__FILE__", line: %d, "
                "client ip: %s, cmd: %d, %s",
                __LINE__, task->client_ip, request->cmd,
                response->error.message);
        return result;
    }
 
    mysql_context = &((FCFGServerContext *)task->thread_data->arg)->mysql_context;
    return fcfg_server_dao_set_config(mysql_context, env, name, value.str);
}

static int fcfg_proto_deal_get_config(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response)
{
    FCFGMySQLContext *mysql_context;
    FCFGProtoGetConfigReq *get_config_req;
    FCFGConfigArray array;
    char env[FCFG_CONFIG_ENV_SIZE];
    char name[FCFG_CONFIG_NAME_SIZE];
    int env_len;
    int name_len;
    int expect_size;
    int data_body_len;
    FCFGProtoGetConfigResp *get_config_resp;
    int result;

    if ((result=FCFG_PROTO_CHECK_BODY_LEN(task, request, response,
                    sizeof(FCFGProtoGetConfigReq),
                    sizeof(FCFGProtoGetConfigReq) + FCFG_CONFIG_MAX_ENV_LEN +
                    FCFG_CONFIG_MAX_NAME_LEN)) != 0)
    {
        return result;
    }

    get_config_req = (FCFGProtoGetConfigReq *)(task->data + sizeof(FCFGProtoHeader));

    env_len = get_config_req->env_len;
    name_len = get_config_req->name_len;

    do {
        if (env_len <= 0 || env_len > FCFG_CONFIG_MAX_ENV_LEN) {
            response->error.length = sprintf(response->error.message,
                    "invalid env length: %d", env_len);
            result = EINVAL;
            break;
        }

        if (name_len <= 0 || name_len  > FCFG_CONFIG_MAX_NAME_LEN) {
            response->error.length = sprintf(response->error.message,
                    "invalid name length: %d", name_len);
            result = EINVAL;
            break;
        }

        data_body_len = sizeof(FCFGProtoGetConfigReq) + env_len + name_len;
        if (request->body_len != data_body_len) {
            response->error.length = sprintf(response->error.message,
                    "invalid body length: %d, expect: %d",
                    request->body_len, data_body_len);
            result = EINVAL;
            break;
        }
        memcpy(env, get_config_req->env, env_len);
        *(env + env_len) = '\0';

        memcpy(name, get_config_req->env + env_len, name_len);
        *(name + name_len) = '\0';

        mysql_context = &((FCFGServerContext *)task->thread_data->arg)->mysql_context;
        result = fcfg_server_dao_get_config(mysql_context, env, name, &array);
        if (result != 0) {
            response->error.length = sprintf(response->error.message,
                    "query config fail, errno: %d", result);
            break;
        }

        if (array.count == 0) {
            response->error.length = sprintf(response->error.message,
                    "config not exist");
            result = ENOENT;
            break;
        }

        expect_size = sizeof(FCFGProtoHeader) + sizeof(FCFGProtoGetConfigResp)
            + array.rows->name.len + array.rows->value.len;
        if (expect_size > task->size) {
            if ((result=free_queue_set_buffer_size(task, expect_size)) != 0) {
                response->error.length = sprintf(response->error.message,
                        "response data is too large: %d", expect_size);
                fcfg_server_dao_free_config_array(&array);
                break;
            }
        }

    } while (0);

    if (result != 0) {
        logError("file: "__FILE__", line: %d, "
                "client ip: %s, cmd: %d, %s",
                __LINE__, task->client_ip, request->cmd,
                response->error.message);
        return result;
    }
 
    get_config_resp = (FCFGProtoGetConfigResp *)(task->data + sizeof(FCFGProtoHeader));
    get_config_resp->status = array.rows->status;
    get_config_resp->name_len = array.rows->name.len;
    int2buff(array.rows->value.len, get_config_resp->value_len);
    long2buff(array.rows->version, get_config_resp->version);
    int2buff(array.rows->create_time, get_config_resp->create_time);
    int2buff(array.rows->update_time, get_config_resp->update_time);
    memcpy(get_config_resp->name, array.rows->name.str, array.rows->name.len);
    memcpy(get_config_resp->name + array.rows->name.len,
           array.rows->value.str, array.rows->value.len);

    response->body_len = sizeof(FCFGProtoGetConfigResp) +
        array.rows->name.len + array.rows->value.len;
    response->cmd = FCFG_PROTO_GET_CONFIG_RESP;
    response->response_done = true;

    fcfg_server_dao_free_config_array(&array);
    return 0;
}

static int fcfg_proto_deal_del_config(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response)
{
    FCFGMySQLContext *mysql_context;
    FCFGProtoDelConfigReq *del_config_req;
    char env[FCFG_CONFIG_ENV_SIZE];
    char name[FCFG_CONFIG_NAME_SIZE];
    int env_len;
    int name_len;
    int data_body_len;
    int result;

    if ((result=FCFG_PROTO_CHECK_BODY_LEN(task, request, response,
                    sizeof(FCFGProtoDelConfigReq),
                    sizeof(FCFGProtoDelConfigReq) + FCFG_CONFIG_MAX_ENV_LEN +
                    FCFG_CONFIG_MAX_NAME_LEN)) != 0)
    {
        return result;
    }

    del_config_req = (FCFGProtoDelConfigReq *)(task->data + sizeof(FCFGProtoHeader));
    env_len = del_config_req->env_len;
    name_len = del_config_req->name_len;

    do {
        if (env_len <= 0 || env_len > FCFG_CONFIG_MAX_ENV_LEN) {
            response->error.length = sprintf(response->error.message,
                    "invalid env length: %d", env_len);
            result = EINVAL;
            break;
        }

        if (name_len <= 0 || name_len  > FCFG_CONFIG_MAX_NAME_LEN) {
            response->error.length = sprintf(response->error.message,
                    "invalid name length: %d", name_len);
            result = EINVAL;
            break;
        }

        data_body_len = sizeof(FCFGProtoDelConfigReq) + env_len + name_len;
        if (request->body_len != data_body_len) {
            response->error.length = sprintf(response->error.message,
                    "invalid body length: %d, expect: %d",
                    request->body_len, data_body_len);
            result = EINVAL;
            break;
        }
        memcpy(env, del_config_req->env, env_len);
        *(env + env_len) = '\0';

        memcpy(name, del_config_req->env + env_len, name_len);
        *(name + name_len) = '\0';

        mysql_context = &((FCFGServerContext *)task->thread_data->arg)->mysql_context;
        result = fcfg_server_dao_del_config(mysql_context, env, name);
        if (result != 0) {
            response->error.length = sprintf(response->error.message,
                    "query config fail, errno: %d", result);
            break;
        }
    } while (0);

    if (result != 0) {
        logError("file: "__FILE__", line: %d, "
                "client ip: %s, cmd: %d, %s",
                __LINE__, task->client_ip, request->cmd,
                response->error.message);
        return result;
    }
 
    return 0;
}

static int fcfg_proto_deal_list_config(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response)
{
    FCFGMySQLContext *mysql_context;
    FCFGProtoListConfigReq *list_config_req;
    FCFGProtoListConfigRespBodyPart *list_config_resp;
    FCFGProtoListConfigRespHeader *resp_header;
    FCFGConfigEntry *entry;
    FCFGConfigEntry *end;
    char *p;
    FCFGConfigArray array;
    char env[FCFG_CONFIG_ENV_SIZE];
    char name[FCFG_CONFIG_NAME_SIZE];
    int env_len;
    int name_len;
    short offset;
    short count;
    int expect_size;
    int data_body_len;
    int result;

    if ((result=FCFG_PROTO_CHECK_BODY_LEN(task, request, response,
                    sizeof(FCFGProtoListConfigReq),
                    sizeof(FCFGProtoListConfigReq) + FCFG_CONFIG_MAX_ENV_LEN +
                    FCFG_CONFIG_MAX_NAME_LEN)) != 0)
    {
        return result;
    }

    list_config_req = (FCFGProtoListConfigReq *)(task->data + sizeof(FCFGProtoHeader));

    env_len = list_config_req->env_len;
    name_len = list_config_req->name_len;

    do {
        if (env_len <= 0 || env_len > FCFG_CONFIG_MAX_ENV_LEN) {
            response->error.length = sprintf(response->error.message,
                    "invalid env length: %d", env_len);
            result = EINVAL;
            break;
        }

        if (name_len < 0 || name_len > FCFG_CONFIG_MAX_NAME_LEN) {
            response->error.length = sprintf(response->error.message,
                    "invalid name length: %d", name_len);
            result = EINVAL;
            break;
        }
        
        data_body_len = sizeof(FCFGProtoListConfigReq) + env_len + name_len;
        if (request->body_len != data_body_len) {
            response->error.length = sprintf(response->error.message,
                    "invalid body length: %d, expect: %d",
                    request->body_len, data_body_len);
            result = EINVAL;
            break;
        }

        memcpy(env, list_config_req->env, env_len);
        *(env + env_len) = '\0';

        memcpy(name, list_config_req->env + env_len, name_len);
        *(name + name_len) = '\0';
        if (*name == '\0') {
            strcpy(name, "%");
        }

        offset = buff2short(list_config_req->limit.offset);
        count = buff2short(list_config_req->limit.count);

        mysql_context = &((FCFGServerContext *)task->thread_data->arg)->mysql_context;
        result = fcfg_server_dao_search_config(mysql_context, env, name,
                offset, count, &array);
        if (result != 0) {
            response->error.length = sprintf(response->error.message,
                    "server query config fail. errno: %d", result);
            break;
        }

        expect_size = sizeof(FCFGProtoHeader) +
            sizeof(FCFGProtoListConfigRespHeader);
        end = array.rows + array.count;
        for (entry = array.rows; entry < end; entry++) {
            expect_size += sizeof(FCFGProtoListConfigRespBodyPart) +
                entry->name.len + entry->value.len;
        }
        if (expect_size > task->size) {
            if ((result=free_queue_set_buffer_size(task, expect_size)) != 0) {
                response->error.length = sprintf(response->error.message,
                        "response data is too large: %d", expect_size);
                fcfg_server_dao_free_config_array(&array);
                break;
            }
        }
    } while (0);

    if (result != 0) {
        logError("file: "__FILE__", line: %d, "
                "client ip: %s, cmd: %d, %s",
                __LINE__, task->client_ip, request->cmd,
                response->error.message);
        return result;
    }

    p = (char *)(task->data + sizeof(FCFGProtoHeader) + 
            sizeof(FCFGProtoListConfigRespHeader));
    for (entry = array.rows; entry < end; entry++) {
        list_config_resp = (FCFGProtoListConfigRespBodyPart *)p;
        list_config_resp->status = entry->status;
        list_config_resp->name_len = entry->name.len;
        int2buff(entry->value.len, list_config_resp->value_len);
        long2buff(entry->version, list_config_resp->version);
        int2buff(entry->create_time, list_config_resp->create_time);
        int2buff(entry->update_time, list_config_resp->update_time);
        memcpy(list_config_resp->name, entry->name.str, entry->name.len);
        memcpy(list_config_resp->name + entry->name.len,
                entry->value.str, entry->value.len);

        p += sizeof(FCFGProtoListConfigRespBodyPart) +
            entry->name.len + entry->value.len;
    }

    resp_header = (FCFGProtoListConfigRespHeader *)(task->data + sizeof(FCFGProtoHeader));
    short2buff(array.count, resp_header->count);

    response->body_len = expect_size - sizeof(FCFGProtoHeader);
    response->cmd = FCFG_PROTO_LIST_CONFIG_RESP;
    response->response_done = true;

    fcfg_server_dao_free_config_array(&array);
    return 0;
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
    FCFGServerTaskArg *task_arg;
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

    task_arg = (FCFGServerTaskArg *)task->arg;
    task_arg->last_recv_pkg_time = g_current_time;
    request.cmd = ((FCFGProtoHeader *)task->data)->cmd;
    request.body_len = task->length - sizeof(FCFGProtoHeader);
    do {
        if (!(task_arg->joined || (request.cmd == FCFG_PROTO_AGENT_JOIN_REQ ||
                        request.cmd == FCFG_PROTO_ADMIN_JOIN_REQ)))
        {
            response.error.length = sprintf(response.error.message,
                    "please join first");
            lerr("client ip: %s, cmd: %d, %s",
                    task->client_ip, request.cmd, response.error.message);
            result = -EINVAL;
            break;
        }

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
                if ((task_arg->waiting_type & expect_waiting_type) == 0) {
                    lerr("client ip: %s, unknow expect cmd: %d, body length: %d",
                            task->client_ip, request.cmd, request.body_len);
                    return -EINVAL;
                }

                task_arg->waiting_type &= ~expect_waiting_type;
                if (request.cmd == FCFG_PROTO_PUSH_RESP) {
                    result = fcfg_proto_deal_push_config_resp(task, &request, &response);
                } else {
                    result = 0;
                }

                task->offset = task->length = 0;
                return result > 0 ? -1 * result : result;
            case FCFG_PROTO_AGENT_JOIN_REQ:
                result = fcfg_proto_deal_agent_join(task, &request, &response);
                break;
            case FCFG_PROTO_ADMIN_JOIN_REQ:
                result = fcfg_proto_deal_admin_join(task, &request, &response);
                break;
            case FCFG_PROTO_ADD_ENV_REQ:
                result = fcfg_proto_deal_add_del_env(task, &request, &response);
                break;
            case FCFG_PROTO_DEL_ENV_REQ:
                result = fcfg_proto_deal_add_del_env(task, &request, &response);
                break;
            case FCFG_PROTO_GET_ENV_REQ:
                result = fcfg_proto_deal_get_env(task, &request, &response);
                break;
            case FCFG_PROTO_LIST_ENV_REQ:
                result = fcfg_proto_deal_list_env(task, &request, &response);
                break;
            case FCFG_PROTO_SET_CONFIG_REQ:
                result = fcfg_proto_deal_set_config(task, &request, &response);
                break;
            case FCFG_PROTO_GET_CONFIG_REQ:
                result = fcfg_proto_deal_get_config(task, &request, &response);
                break;
            case FCFG_PROTO_LIST_CONFIG_REQ:
                result = fcfg_proto_deal_list_config(task, &request, &response);
                break;
            case FCFG_PROTO_DEL_CONFIG_REQ:
                result = fcfg_proto_deal_del_config(task, &request, &response);
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

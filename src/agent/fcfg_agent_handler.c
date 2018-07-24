//fcfg_agent_handler.c

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
#include "fcfg_agent_global.h"
#include "fcfg_agent_func.h"
#include "fcfg_agent_handler.h"

int fcfg_agent_handler_init()
{
    return 0;
}

int fcfg_agent_handler_destroy()
{   
    return 0;
}

void fcfg_agent_task_finish_cleanup(struct fast_task_info *task)
{
    sf_task_finish_clean_up(task);
}

static int fcfg_agent_set_config_version(int64_t version)
{
    int ret;
    struct shmcache_value_info value;
    struct shmcache_key_info key;
    
    key.data = g_agent_global_vars.shm_version_key;
    key.length = strlen(g_agent_global_vars.shm_version_key);
    value.data = (char *)&version;
    value.length = sizeof(version);
    value.expires = SHMCACHE_NEVER_EXPIRED;
    value.options = SHMCACHE_SERIALIZER_STRING;
    ret = shmcache_set_ex(&g_agent_global_vars.shm_context,
            &key,
            &value);
    if (ret) {
        lerr("shmcache_set_ex fail:%d, %s, version:%"PRId64,
                ret, strerror(ret), version);
    }

    return ret;
}

static int fcfg_agent_get_config_version()
{
    char buff[64];
    int ret;
    int64_t version;
    struct shmcache_value_info value;
    struct shmcache_key_info key;
    
    key.data = g_agent_global_vars.shm_version_key;
    key.length = strlen(g_agent_global_vars.shm_version_key);
    ret = shmcache_get(&g_agent_global_vars.shm_context,
            &key,
            &value);
    if (ret) {
        lerr("shmcache_get fail:%d, %s", ret, strerror(ret));
        return 0;
    }
    memcpy(buff, value.data, value.length);
    buff[value.length] = '\0';
    version = atol(buff);

    return version;
}


static int fcfg_do_task_push_config(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response)
{
    int ret;
    int i;
    int size;
    int64_t max_version;
    FCFGPushConfigHeader fcfg_push_header;
    FCFGProtoPushConfigHeader *fcfg_push_header_pro;
    FCFGProtoPushConfigBodyPart *fcfg_push_body_pro;
    FCFGPushConfigBodyPart fcfg_push_body_data;
    struct shmcache_key_info key;
    struct shmcache_value_info value;

    fcfg_push_header_pro = (FCFGProtoPushConfigHeader *)(task->data + sizeof(FCFGProtoHeader));
    fcfg_extract_push_config_header(fcfg_push_header_pro, &fcfg_push_header);

    fcfg_push_body_pro = (FCFGProtoPushConfigBodyPart *)(fcfg_push_header_pro +
            1);
    ret = fcfg_check_push_config_body_len(&fcfg_push_header, fcfg_push_body_pro,
            request->body_len - sizeof(FCFGProtoPushConfigHeader));
    if (ret) {
        lerr("fcfg_check_push_config_body_len fail.count:%d",
                fcfg_push_header.count);
        return ret;
    }
    size = sizeof(FCFGPushConfigBodyPart);
    for (i = 0; i < fcfg_push_header.count; i++) {
        fcfg_extract_push_config_body_data(fcfg_push_body_pro, &fcfg_push_body_data);
        key.data = fcfg_push_body_pro->name;
        key.length = fcfg_push_body_data.name_len;
        value.data = fcfg_push_body_pro->name + fcfg_push_body_data.name_len;
        value.length = fcfg_push_body_data.value_len;
        value.options = SHMCACHE_SERIALIZER_STRING;
        value.expires = SHMCACHE_NEVER_EXPIRED;
        if (fcfg_push_body_data.status == FCFG_CONFIG_STATUS_NORMAL) {
            ret = shmcache_set_ex(&g_agent_global_vars.shm_context, &key, &value);
        } else {
            ret = shmcache_delete(&g_agent_global_vars.shm_context, &key);
        }
        if (ret) {
            lerr ("shmcache_set_ex/delete fail:status:%d, %d, %s",
                    fcfg_push_body_data.status, ret, strerror(ret));
        }

        /* the last one is the max version that is ensured by sender */
        max_version = fcfg_push_body_data.version;

        fcfg_push_body_pro = (FCFGProtoPushConfigBodyPart *)(((char *)fcfg_push_body_pro) + size +
                              fcfg_push_body_data.name_len +
                              fcfg_push_body_data.value_len);
    }

    fcfg_agent_set_config_version(max_version);

    return 0;
}

static int fcfg_proto_deal_push_config (struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response)
{
    int result = 0;
    if ((result=FCFG_PROTO_CHECK_MIN_BODY_LEN(task, request, response,
                    sizeof(FCFGProtoPushConfigHeader))) != 0) {
        return result;
    }

    if ((result=fcfg_do_task_push_config(task, request, response)) != 0) {
        return result;
    }

    response->response_done = true;
    response->cmd = FCFG_PROTO_PUSH_RESP;
    return 0;
}

int fcfg_agent_deal_task(struct fast_task_info *task)
{
    FCFGProtoHeader *proto_header;
    FCFGRequestInfo request;
    FCFGResponseInfo response;
    int result;
    int r;
    int64_t tbegin;
    int time_used;

    tbegin = get_current_time_ms();
    response.cmd = FCFG_PROTO_ACTIVE_TEST_RESP;
    response.body_len = 0;
    response.error.length = 0;
    response.error.message[0] = '\0';
    response.response_done = false;

    request.cmd = ((FCFGProtoHeader *)task->data)->cmd;
    request.body_len = task->length - sizeof(FCFGProtoHeader);
    do {
        switch (request.cmd) {
            case FCFG_PROTO_ACTIVE_TEST_REQ:
                result = fcfg_proto_deal_actvie_test(task, &request, &response);
                break;
            case FCFG_PROTO_PUSH_CONFIG:
                result = fcfg_proto_deal_push_config(task, &request, &response);
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
int fcfg_agent_shm_init ()
{
    return shmcache_init_from_file(&g_agent_global_vars.shm_context,
            g_agent_global_vars.shm_config_file);
}

int fcfg_agent_join ()
{
    int ret;
    char buff[128];
    int64_t version;
    FCFGProtoHeader fcfg_header_resp_pro;
    FCFGResponseInfo resp_info;
    FCFGJoinResp join_resp_data;

    version = fcfg_agent_get_config_version();

    while (true) {
        if (g_agent_global_vars.join_conn.sock >= 0) {
            conn_pool_disconnect_server(&g_agent_global_vars.join_conn);
        }
        ret = conn_pool_connect_server(&g_agent_global_vars.join_conn, g_sf_global_vars.connect_timeout);
        if (ret) {
            lerr ("conn_pool_connect_server fail:%d, %s", ret, strerror(ret));
            sleep(1);
            continue;
        }
        fcfg_proto_set_join_req(buff, g_agent_global_vars.env, version);

        ret = tcpsenddata_nb(g_agent_global_vars.join_conn.sock, buff,
                sizeof(FCFGProtoHeader) + sizeof(FCFGProtoJoinReq), g_sf_global_vars.network_timeout);
        if (ret) {
            lerr("tcpsenddata_nb fail.:%d, %s\n", ret, strerror(ret));
            sleep(1);
            continue;
        }
        ret = tcprecvdata_nb_ex(g_agent_global_vars.join_conn.sock, &fcfg_header_resp_pro,
                sizeof(FCFGProtoJoinReq), g_sf_global_vars.network_timeout, NULL);
        if (ret) {
            lerr("tcprecvdata_nb_ex fail.:%d, %s\n", ret, strerror(ret));
            sleep(1);
            continue;
        }
        fcfg_proto_response_extract(&fcfg_header_resp_pro, &resp_info);
        if (resp_info.cmd != FCFG_PROTO_JION_RESP) {
            if (resp_info.body_len) {
                ret = tcprecvdata_nb_ex(g_agent_global_vars.join_conn.sock, resp_info.error.message,
                        resp_info.body_len, g_sf_global_vars.network_timeout, NULL);
            } else {
                resp_info.error.message[0] = '\0';
            }
            lerr("agent join response err. resp cmd:%d, error msg:%s",
                    resp_info.cmd, resp_info.error.message);
            sleep(1);
            continue;
        } else {
            if (resp_info.body_len) {
                ret = tcprecvdata_nb_ex(g_agent_global_vars.join_conn.sock, buff,
                        resp_info.body_len, g_sf_global_vars.network_timeout, NULL);
                if (ret) {
                    lerr("tcprecvdata_nb_ex fail.err:%d, err info:%s\n",
                            ret, strerror(ret));
                    sleep(1);
                    continue;
                } else {
                    fcfg_extract_join_resp(&join_resp_data,
                            (FCFGProtoJoinResp *)buff);
                    linfo("join server. resp version:%"PRId64, join_resp_data.center_cfg_version);
                    conn_pool_disconnect_server(&g_agent_global_vars.join_conn);
                    if (join_resp_data.center_cfg_version < version) {
                        ret = shmcache_clear(&g_agent_global_vars.shm_context);
                        if (ret) {
                            lerr("shmcache_remove_all fail. %d, %s", ret,
                                    strerror(ret));
                            return ret;
                        }
                    }
                    break;
                }
            } else {
                lerr("resp_info.body_len is 0");
                sleep(1);
                continue;
            }
        }
    }

    return 0;
}

void *fcfg_agent_alloc_thread_extra_data(const int thread_index)
{
    return NULL;
}

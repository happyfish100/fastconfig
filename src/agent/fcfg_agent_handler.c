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
#include "fcfg_agent_types.h"
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

static int fcfg_agent_get_config_version()
{
    char key[128] = {0};
    int size;
    int ret;
    struct shmcache_value_info value;
    struct shmcache_key_info key;
    
    key->data = g_agent_global_vars.shm_version_key;
    key->length = strlen(g_agent_global_vars.shm_version_key);
    ret = shmcache_get(&g_agent_global_vars.context,
            &key,
            &value);
    if (ret) {
        lerr("shmcache_get fail:%d, %s", ret, strerror(ret));
        return 0;
    }

}

int fcfg_agent_shm_init ()
{
    return shmcache_init_from_file(&g_agent_global_vars.context,
            g_agent_global_vars.shm_config_file);
}

int fcfg_agent_join ()
{
    int ret;
    char buff[128];
    FCFGProtoHeader *fcfg_header_pro;
    FCFGProtoJoinReq *fcfg_join_req_pro;

    ret = conn_pool_connect_server(&g_agent_global_vars.join_conn, g_sf_global_vars.connect_timeout);
    if (ret) {
        lerr ("conn_pool_connect_server fail:%d, %s", ret, strerror(ret));
        return ret;
    }
    fcfg_header_pro = (FCFGProtoHeader *)buff;
    fcfg_header_pro->cmd = FCFG_PROTO_JION_REQ;
    fcfg_join_req_pro = buff + sizeof(FCFGProtoHeader);

}

void *fcfg_agent_alloc_thread_extra_data(const int thread_index)
{
    return NULL;
}

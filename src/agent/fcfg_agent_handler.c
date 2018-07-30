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
    char buff[FCFG_CONFIG_ENV_SIZE];
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


static int fcfg_set_push_config(const char *data,
        const int body_len)
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

    fcfg_push_header_pro = (FCFGProtoPushConfigHeader *)(data + sizeof(FCFGProtoHeader));
    fcfg_extract_push_config_header(fcfg_push_header_pro, &fcfg_push_header);

    fcfg_push_body_pro = (FCFGProtoPushConfigBodyPart *)(fcfg_push_header_pro +
            1);
    ret = fcfg_check_push_config_body_len(&fcfg_push_header, fcfg_push_body_pro,
            body_len - sizeof(FCFGProtoPushConfigHeader));
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
        if (fcfg_push_body_data.status == FCFG_CONFIG_STATUS_NORMAL) {
            value.data = fcfg_push_body_pro->name + fcfg_push_body_data.name_len;
            value.length = fcfg_push_body_data.value_len;
            value.options = SHMCACHE_SERIALIZER_STRING;
            value.expires = SHMCACHE_NEVER_EXPIRED;
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

int fcfg_agent_shm_init ()
{
    return shmcache_init_from_file(&g_agent_global_vars.shm_context,
            g_agent_global_vars.shm_config_file);
}

static int fcfg_admin_check_response(ConnectionInfo *join_conn,
        FCFGResponseInfo *resp_info, int network_timeout, unsigned char resp_cmd)
{
    if (resp_info->cmd == resp_cmd && resp_info->status == 0) {
        return 0;
    } else {
        if (resp_info->body_len) {
            tcprecvdata_nb_ex(join_conn->sock, resp_info->error.message,
                    resp_info->body_len, network_timeout, NULL);
        } else {
            resp_info->error.message[0] = '\0';
        }
        return 1;
    }

}
int fcfg_send_agent_join_request(ConnectionInfo *join_conn, int64_t version)
{
    int ret;
    char buff[1024];
    int req_len;
    FCFGResponseInfo resp_info;
    int network_timeout = g_agent_global_vars.network_timeout;
    int connect_timeout = g_agent_global_vars.connect_timeout;

    fcfg_proto_set_join_req(buff, g_agent_global_vars.env, version, &req_len);
    ret = send_and_recv_response_header(join_conn, buff, req_len, &resp_info,
            network_timeout, connect_timeout);
    if (ret) {
        lerr("send_and_recv_response_header fail. ret:%d, %s",
                ret, strerror(ret));
        return ret;
    }
    ret = fcfg_admin_check_response (join_conn, &resp_info, network_timeout, FCFG_PROTO_AGENT_JOIN_RESP);
    if (ret) {
        lerr("agent join server fail. %s "
             "conn: %s:%d",
                resp_info.error.message, join_conn->ip_addr, join_conn->port);
    }

    return ret;
}

int fcfg_agent_send_header_resp(ConnectionInfo *join_conn, unsigned char resp_cmd)
{
    FCFGProtoHeader fcfg_header_resp_pro; 
    memset(&fcfg_header_resp_pro, 0, sizeof(FCFGProtoHeader));
    fcfg_header_resp_pro.cmd = resp_cmd;
    return tcpsenddata_nb(join_conn->sock, &fcfg_header_resp_pro,
                    sizeof(FCFGProtoHeader), g_agent_global_vars.network_timeout);
}

int fcfg_agent_recv_server_active_test (ConnectionInfo *join_conn)
{
    return fcfg_agent_send_header_resp(join_conn, FCFG_PROTO_ACTIVE_TEST_RESP);
}
int fcfg_agent_recv_server_psuh_config (ConnectionInfo *join_conn, int body_len)
{
    int ret;
    char buff[256 * 1024];

    while (g_sf_global_vars.continue_flag) {
        ret = tcprecvdata_nb_ex(join_conn->sock, buff,
                        body_len, g_agent_global_vars.network_timeout, NULL);
        if (ret == 0 || ret != ETIMEDOUT) {
            break;
        }
        lerr ("tcprecvdata_nb_ex ret:%d, %s", ret, strerror(ret));
        usleep(100000);
    }
    fcfg_set_push_config(buff, body_len);

    return fcfg_agent_send_header_resp(join_conn, FCFG_PROTO_PUSH_RESP);
}

int fcfg_agent_recv_server_push (ConnectionInfo *join_conn)
{
    int ret;
    FCFGResponseInfo resp_info;
    FCFGProtoHeader fcfg_header_resp_pro;

    if ((ret = tcprecvdata_nb_ex(join_conn->sock, &fcfg_header_resp_pro,
                    sizeof(FCFGProtoHeader), g_agent_global_vars.network_timeout, NULL)) != 0) {
        return ret;
    }

    fcfg_proto_response_extract(&fcfg_header_resp_pro,&resp_info);
    switch (fcfg_header_resp_pro.cmd) {
        case FCFG_PROTO_ACTIVE_TEST_REQ:
            ret = fcfg_agent_recv_server_active_test(join_conn);
            break;
        case FCFG_PROTO_PUSH_CONFIG:
            ret = fcfg_agent_recv_server_psuh_config(join_conn,
                    resp_info.body_len);
            break;
        default:
            lerr ("get push config error cmd:%d", fcfg_header_resp_pro.cmd);
            ret = -1;
            break;
    }

    return ret;
}
static int fcfg_agent_do_conn_config_server (ConnectionInfo **conn)
{
    int ret;
    int server_index;
    ConnectionInfo *join_conn;
    int index;

    index = 0;
    srand(time(NULL));
    server_index = rand() % g_agent_global_vars.server_count;
    while (index < g_agent_global_vars.server_count) {
        join_conn = g_agent_global_vars.join_conn + server_index;
        if ((ret = conn_pool_connect_server(join_conn,
                        g_agent_global_vars.connect_timeout)) != 0) {
            lerr("conn_pool_connect_server fail. server index[%d] %s:%d, ret:%d, %s",
                    server_index,
                    join_conn->ip_addr,
                    join_conn->port,
                    ret, strerror(ret));
            server_index = (server_index + 1) % g_agent_global_vars.server_count;
            index ++;
        } else {
            /* connect success */
            *conn = join_conn;
            break;
        }
    }

    return ret;
}
int fcfg_agent_wait_config_server_loop ()
{
    int ret;
    int need_join;
    int64_t version;
    ConnectionInfo *join_conn = NULL;

    version = fcfg_agent_get_config_version();

    ret = 0;
    while (g_sf_global_vars.continue_flag) {
        if (join_conn == NULL || (ret != 0 && ret != ETIMEDOUT)) {
            if (join_conn && join_conn->sock >= 0) {
                conn_pool_disconnect_server(join_conn);
            }
            ret = fcfg_agent_do_conn_config_server(&join_conn);
            if (ret) {
                join_conn = NULL;
                lerr ("join server conn_pool_connect_server fail:%d, %s", ret, strerror(ret));
                sleep(1);
                continue;
            }
            need_join = 1;

        }
        if (need_join) {
            ret = fcfg_send_agent_join_request(join_conn, version);
            if (ret) {
                lerr ("join server fcfg_send_agent_join_request fail.%d, %s", ret, strerror(ret));
                sleep(1);
                continue;
            }
            need_join = 0;
        }
        linfo("agent join server success.conn: %s:%d",
                join_conn->ip_addr, join_conn->port);
        ret = fcfg_agent_recv_server_push(join_conn);
        if (ret) {
            lerr ("fcfg_agent_recv_server_push fail");
            continue;
        }
    }

    return 0;
}


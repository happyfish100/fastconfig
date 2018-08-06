#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "common/fcfg_proto.h"
#include "fastcommon/sockopt.h"
#include "fcfg_admin_func.h"
#include "fcfg_admin_get_config.h"

/*
static bool show_usage = false;
FCFGAdminGetGlobal g_fcfg_admin_get_vars;
static void usage(char *program)
{
    logInfo("file: "__FILE__", line: %d""Usage: %s options, the options as:\n"
            "\t -h help\n"
            "\t -c <config-filename>\n"
            "\t -e <config-env>\n"
            "\t -n <config-name>\n"
            "\n", program);
}

static void parse_args(int argc, char **argv)
{
    int ch;
    int found = 0;

    while ((ch = getopt(argc, argv, "hc:e:n:")) != -1) {
        found = 1;
        switch (ch) {
            case 'c':
                g_fcfg_admin_get_vars.config_file = optarg;
                break;
            case 'e':
                g_fcfg_admin_get_vars.config_env = optarg;
                break;
            case 'n':
                g_fcfg_admin_get_vars.config_name = optarg;
                break;
            case 'h':
            default:
                show_usage = true;
                break;
        }
    }
    if (found == 0 ||
        g_fcfg_admin_get_vars.config_file == NULL ||
        g_fcfg_admin_get_vars.config_env == NULL ||
        g_fcfg_admin_get_vars.config_name == NULL) {
        show_usage = true;
    }
}
*/

void fcfg_set_admin_get_config(char *buff, const char *env,
        const char *config_name, int *body_len)
{
    FCFGProtoGetConfigReq *get_config_req = (FCFGProtoGetConfigReq *)buff;
    unsigned char env_len = strlen(env);
    unsigned char name_len = strlen(config_name);
    get_config_req->env_len = env_len;
    get_config_req->name_len = name_len;
    memcpy(get_config_req->env,
           env,
           env_len);
    memcpy(get_config_req->env + env_len, config_name,
           name_len);
    *body_len = sizeof(FCFGProtoGetConfigReq) + env_len + name_len;
}

static int fcfg_admin_extract_to_array (char *buff, int len, FCFGConfigArray *array)
{
    int size;
    int ret;
    FCFGProtoGetConfigResp *get_config_resp = (FCFGProtoGetConfigResp *)buff;

    array->count = 1;
    array->rows = (FCFGConfigEntry *)malloc(sizeof(FCFGConfigEntry));
    if (array->rows == NULL) {
        logInfo("file: "__FILE__", line: %d, "
                "malloc %ld bytes fail", __LINE__, sizeof(FCFGConfigEntry));
        return ENOMEM;
    }

    ret = fcfg_admin_config_set_entry(get_config_resp, array->rows, &size);
    if (ret || (size != len)) {
        logInfo("file: "__FILE__", line: %d"
                "fcfg_admin_config_set_entry fail"
                " ret:%d, size:%d, len:%d", __LINE__, ret, size, len); 
        return -1;
    }
    return 0;
}

int fcfg_admin_get_config_response(ConnectionInfo *join_conn,
        FCFGResponseInfo *resp_info, int network_timeout, FCFGConfigArray *array)
{
    char buff[FCFG_CONFIG_VALUE_SIZE + 1024];
    int ret;
    if (resp_info->body_len == 0) {
        return -1;
    }
    if (resp_info->body_len > sizeof(buff)) {
        logInfo("file: "__FILE__", line: %d"
                "body_len is too long %d", __LINE__, resp_info->body_len);
        return -1;
    }
    ret = tcprecvdata_nb_ex(join_conn->sock, buff,
            resp_info->body_len, network_timeout, NULL);
    if (ret) {
        logInfo("file: "__FILE__", line: %d"
                "tcprecvdata_nb_ex fail %d", __LINE__, resp_info->body_len);
        return -1;
    }

    return fcfg_admin_extract_to_array(buff, resp_info->body_len, array);
}

int fcfg_admin_get_config (struct fcfg_context *fcfg_context,
        const char *env, const char *config_name, FCFGConfigArray *array)
{
    int ret;
    char buff[1024];
    int body_len;
    int size;
    FCFGResponseInfo resp_info;
    FCFGProtoHeader *fcfg_header_proto;

    ConnectionInfo *join_conn;
    join_conn = fcfg_context->join_conn + fcfg_context->join_index;
    fcfg_header_proto = (FCFGProtoHeader *)buff;
    fcfg_set_admin_get_config(buff + sizeof(FCFGProtoHeader), env, config_name, &body_len);
    fcfg_set_admin_header(fcfg_header_proto, FCFG_PROTO_GET_CONFIG_REQ, body_len);
    size = sizeof(FCFGProtoHeader) + body_len;
    ret = send_and_recv_response_header(join_conn, buff, size, &resp_info,
            fcfg_context->network_timeout, fcfg_context->connect_timeout);
    if (ret) {
        logInfo("file: "__FILE__", line: %d"
                "send_and_recv_response_header fail. ret:%d, %s\n",
                __LINE__, ret, strerror(ret));
        return ret;
    }
    ret = fcfg_admin_check_response(join_conn, &resp_info,
            fcfg_context->network_timeout, FCFG_PROTO_GET_CONFIG_RESP);
    if (ret) {
        logInfo("file: "__FILE__", line: %d"
                "get config fail.err info: %s\n",
                __LINE__, resp_info.error.message);
    } else {
        ret = fcfg_admin_get_config_response(join_conn, &resp_info,
                fcfg_context->network_timeout, array);
    }

    if (ret == 0) {
        logInfo("file: "__FILE__", line: %d"
                "get config success !", __LINE__);
    }
    return ret;
}

int fcfg_admin_config_get (struct fcfg_context *fcfg_context,
        const char *env, const char *config_name, FCFGConfigArray *array)
{
    int ret;
    memset(array, 0, sizeof(FCFGConfigArray));

    if ((ret = fcfg_send_admin_join_request(fcfg_context,
            fcfg_context->network_timeout,
            fcfg_context->connect_timeout)) != 0) {
        return ret;
    }

    ret = fcfg_admin_get_config(fcfg_context, env, config_name, array);
    return ret;
}

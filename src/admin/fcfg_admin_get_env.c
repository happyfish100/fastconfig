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
#include "fastcommon/sockopt.h"
#include "common/fcfg_proto.h"
#include "fcfg_admin_func.h"
#include "fcfg_admin_get_env.h"

/*
static bool show_usage = false;
FCFGAdminGetEnvGlobal g_fcfg_admin_get_env;
static void usage(char *program)
{
    logInfo("file: "__FILE__", line: %d""Usage: %s options, the options as:\n"
            "\t -h help\n"
            "\t -c <config-filename>\n"
            "\t -e <config-env>\n"
            "\n", program);
}

static void parse_args(int argc, char **argv)
{
    int ch;
    int found = 0;

    while ((ch = getopt(argc, argv, "hc:e:")) != -1) {
        found = 1;
        switch (ch) {
            case 'c':
                g_fcfg_admin_get_env.config_file = optarg;
                break;
            case 'e':
                g_fcfg_admin_get_env.config_env = optarg;
                break;
            case 'h':
            default:
                show_usage = true;
                break;
        }
    }
    if (found == 0 ||
        g_fcfg_admin_get_env.config_file == NULL ||
        g_fcfg_admin_get_env.config_env == NULL) {
        show_usage = true;
    }
}
*/

void fcfg_set_admin_get_env(const char *env, char *buff,
        int *body_len)
{
    FCFGProtoGetEnvReq *get_env_req = (FCFGProtoGetEnvReq *)buff;
    unsigned char env_len = strlen(env);
    memcpy(get_env_req->env, env,
           env_len);
    *body_len = sizeof(FCFGProtoGetEnvReq) + env_len;
}

static int fcfg_admin_extract_to_array (char *buff, int len, FCFGEnvArray *array)
{
    int ret;
    int env_size;
    FCFGProtoGetEnvResp *get_env_resp = (FCFGProtoGetEnvResp *)buff;

    array->count = 1;
    array->rows = (FCFGEnvEntry *)malloc(sizeof(FCFGEnvEntry));
    if (array->rows == NULL) {
        logInfo("file: "__FILE__", line: %d, "
                "malloc %ld bytes fail", __LINE__, sizeof(FCFGEnvEntry));
        fcfg_free_env_array(array);
        return ENOMEM;
    }
    ret = fcfg_admin_env_set_entry(get_env_resp, array->rows, &env_size);

    if (ret || (env_size != len)) {
        logInfo("file: "__FILE__", line: %d, "
                "fcfg_admin_env_set_entry fail. ret:%d, env_size: %d, len: %d",
                __LINE__, ret, env_size, len);
        return -1;
    }

    return 0;
}

int fcfg_admin_get_env_response(ConnectionInfo *join_conn,
        FCFGResponseInfo *resp_info, int network_timeout, FCFGEnvArray *array)
{
    char buff[1024];
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


int fcfg_admin_get_env (struct fcfg_context *fcfg_context, const char *env, FCFGEnvArray *array)
{
    int ret;
    char buff[1024];
    int body_len;
    int size;
    ConnectionInfo *join_conn;
    FCFGResponseInfo resp_info;
    FCFGProtoHeader *fcfg_header_proto;

    fcfg_header_proto = (FCFGProtoHeader *)buff;
    fcfg_set_admin_get_env(env, buff + sizeof(FCFGProtoHeader), &body_len);
    join_conn = fcfg_context->join_conn + fcfg_context->join_index;
    fcfg_set_admin_header(fcfg_header_proto, FCFG_PROTO_GET_ENV_REQ, body_len);
    size = sizeof(FCFGProtoHeader) + body_len;
    ret = send_and_recv_response_header(join_conn, buff, size, &resp_info,
            fcfg_context->network_timeout, fcfg_context->connect_timeout);
    if (ret) {
        logInfo("file: "__FILE__", line: %d"
                "send_and_recv_response_header fail. ret:%d, %s",
                __LINE__, ret, strerror(ret));
        return ret;
    }
    ret = fcfg_admin_check_response(join_conn,
            &resp_info,
            fcfg_context->network_timeout, FCFG_PROTO_GET_ENV_RESP);
    if (ret) {
        logInfo("file: "__FILE__", line: %d"
                "get env fail.err info: %s",
                __LINE__,
                resp_info.error.message);
    } else {
        ret = fcfg_admin_get_env_response(join_conn, &resp_info,
                fcfg_context->network_timeout, array);
    }

    if (ret == 0) {
        logInfo("file: "__FILE__", line: %d"
                "get env success !", __LINE__);
    }
    return ret;
}

int fcfg_admin_env_get (struct fcfg_context *fcfg_context, const char *env,
        FCFGEnvArray *array)
{
    int ret;
    memset(array, 0, sizeof(FCFGEnvArray));

    if ((ret = fcfg_send_admin_join_request(fcfg_context,
            fcfg_context->network_timeout,
            fcfg_context->connect_timeout)) != 0) {
        goto END;
    }

    ret = fcfg_admin_get_env(fcfg_context, env, array);

END:
    log_destroy();
    return ret;
}


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
#include "fcfg_admin_func.h"
#include "fcfg_admin_set_config.h"

/*
static bool show_usage = false;
FCFGAdminSetGlobal g_fcfg_admin_set_vars;
static void usage(char *program)
{
    logInfo("file: "__FILE__", line: %d""Usage: %s options, the options as:\n"
            "\t -h help\n"
            "\t -c <config-filename>\n"
            "\t -e <config-env>\n"
            "\t -n <config-name>\n"
            "\t -v <config-value>\n"
            "\n", program);
}

static void parse_args(int argc, char **argv)
{
    int ch;
    int found = 0;

    while ((ch = getopt(argc, argv, "hc:e:n:v:")) != -1) {
        found = 1;
        switch (ch) {
            case 'c':
                g_fcfg_admin_set_vars.config_file = optarg;
                break;
            case 'e':
                g_fcfg_admin_set_vars.config_env = optarg;
                break;
            case 'n':
                g_fcfg_admin_set_vars.config_name = optarg;
                break;
            case 'v':
                g_fcfg_admin_set_vars.config_value = optarg;
                break;
            case 'h':
            default:
                show_usage = true;
                break;
        }
    }
    if (found == 0 ||
        g_fcfg_admin_set_vars.config_file == NULL ||
        g_fcfg_admin_set_vars.config_env == NULL ||
        g_fcfg_admin_set_vars.config_name == NULL ||
        g_fcfg_admin_set_vars.config_value == NULL) {
        show_usage = true;
    }
}
*/
void fcfg_set_admin_set_config(char *buff,const char *env,
        const char *config_name, const char *config_value,
        int *body_len)
{
    FCFGProtoSetConfigReq *set_config_req = (FCFGProtoSetConfigReq *)buff;
    unsigned char env_len = strlen(env);
    unsigned char name_len = strlen(config_name);
    int value_len = strlen(config_value);

    set_config_req->env_len = env_len;
    set_config_req->name_len = name_len;
    int2buff(value_len, set_config_req->value_len);
    memcpy(set_config_req->env, env,
           env_len);
    memcpy(set_config_req->env + env_len,
           config_name,
           name_len);
    memcpy(set_config_req->env + env_len + name_len,
           config_value,
           value_len);
    *body_len = sizeof(FCFGProtoSetConfigReq) + env_len + name_len + value_len;
}

int fcfg_admin_set_config (struct fcfg_context *fcfg_context,
        const char *env, const char *config_name, const char *config_value)
{
    int ret;
    char buff[1024];
    int body_len;
    int size;
    FCFGResponseInfo resp_info;
    ConnectionInfo *join_conn;
    FCFGProtoHeader *fcfg_header_proto;

    join_conn = fcfg_context->join_conn + fcfg_context->join_index;
    fcfg_header_proto = (FCFGProtoHeader *)buff;
    fcfg_set_admin_set_config(buff + sizeof(FCFGProtoHeader), env, config_name,
            config_value, &body_len);
    fcfg_set_admin_header(fcfg_header_proto, FCFG_PROTO_SET_CONFIG_REQ, body_len);
    size = sizeof(FCFGProtoHeader) + body_len;
    ret = send_and_recv_response_header(join_conn, buff, size, &resp_info,
            fcfg_context->network_timeout, fcfg_context->connect_timeout);
    if (ret) {
        logInfo("file: "__FILE__", line: %d"
                "send_and_recv_response_header fail. ret:%d, %s",
                __LINE__, ret, strerror(ret));
        return ret;
    }
    ret = fcfg_admin_check_response(join_conn, &resp_info,
            fcfg_context->network_timeout, FCFG_PROTO_ACK);
    if (ret) {
        logInfo("file: "__FILE__", line: %d"
                "set config fail.err info: %s",
                __LINE__, resp_info.error.message);
    } else {
        logInfo("file: "__FILE__", line: %d"
                "set config success !", __LINE__);
    }

    return ret;
}

int fcfg_admin_config_set (struct fcfg_context *fcfg_context,
        const char *env, const char *config_name, const char *config_value)
{
    int ret;

    if ((ret = fcfg_send_admin_join_request(fcfg_context,
            fcfg_context->network_timeout,
            fcfg_context->connect_timeout)) != 0) {
        return ret;
    }

    ret = fcfg_admin_set_config(fcfg_context, env, config_name, config_value);

    return ret;
}

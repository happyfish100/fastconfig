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
#include "fcfg_admin_del_config.h"

/*
static bool show_usage = false;
FCFGAdminDelGlobal g_fcfg_admin_del_vars;
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
                g_fcfg_admin_del_vars.config_file = optarg;
                break;
            case 'e':
                g_fcfg_admin_del_vars.config_env = optarg;
                break;
            case 'n':
                g_fcfg_admin_del_vars.config_name = optarg;
                break;
            case 'h':
            default:
                show_usage = true;
                break;
        }
    }
    if (found == 0 ||
        g_fcfg_admin_del_vars.config_file == NULL ||
        g_fcfg_admin_del_vars.config_env == NULL ||
        g_fcfg_admin_del_vars.config_name == NULL) {
        show_usage = true;
    }
}
*/

void fcfg_set_admin_del_config(char *buff, const char *env,
        const char *config_name, int *body_len)
{
    FCFGProtoDelConfigReq *del_config_req = (FCFGProtoDelConfigReq *)buff;
    unsigned char env_len = strlen(env);
    unsigned char name_len = strlen(config_name);
    
    del_config_req->env_len = env_len;
    del_config_req->name_len = name_len;
    memcpy(del_config_req->env,
           env,
           env_len);
    memcpy(del_config_req->env + env_len, config_name,
           name_len);
    *body_len = sizeof(FCFGProtoDelConfigReq) + env_len + name_len;
}

int fcfg_admin_del_config (struct fcfg_context *fcfg_context,
        const char *env, const char *config_name)
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
    fcfg_set_admin_del_config(buff + sizeof(FCFGProtoHeader), env, config_name, &body_len);
    fcfg_set_admin_header(fcfg_header_proto, FCFG_PROTO_DEL_CONFIG_REQ, body_len);
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
            fcfg_context->network_timeout, FCFG_PROTO_ACK);
    if (ret) {
        logInfo("file: "__FILE__", line: %d"
                "del config fail.err info: %s\n",
                __LINE__, resp_info.error.message);
    } else {
        logInfo("file: "__FILE__", line: %d"
                "del config success !", __LINE__);
    }

    return ret;
}

int fcfg_admin_config_del (struct fcfg_context *fcfg_context,
        const char *env, const char *config_name)
{
    int ret;

    if ((ret = fcfg_send_admin_join_request(fcfg_context,
            fcfg_context->network_timeout,
            fcfg_context->connect_timeout)) != 0) {
        return ret;
    }

    ret = fcfg_admin_del_config(fcfg_context, env, config_name);
    return ret;
}

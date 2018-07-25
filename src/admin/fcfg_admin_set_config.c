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

static bool show_usage = false;
FCFGAdminSetGlobal g_fcfg_admin_set_vars;
static void usage(char *program)
{
    fprintf(stderr, "Usage: %s options, the options as:\n"
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

    while ((ch = getopt(argc, argv, "hc:e:n:v:")) != -1) {
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
                usage(argv[0]);
                break;
        }
    }
}

void fcfg_set_admin_set_config(FCFGProtoSetConfigReq *fcfg_set_config_proto,
        int *body_len)
{
    unsigned char env_len = strlen(g_fcfg_admin_set_vars.config_env);
    unsigned char name_len = strlen(g_fcfg_admin_set_vars.config_name);
    int value_len = strlen(g_fcfg_admin_set_vars.config_value);
    fcfg_set_config_proto->env_len = env_len;
    fcfg_set_config_proto->name_len = name_len;
    int2buff(value_len, fcfg_set_config_proto->value_len);
    memcpy(fcfg_set_config_proto->env, g_fcfg_admin_set_vars.config_env,
           env_len);
    memcpy(fcfg_set_config_proto->env + env_len,
           g_fcfg_admin_set_vars.config_name,
           name_len);
    memcpy(fcfg_set_config_proto->env +
           env_len +
           name_len,
           g_fcfg_admin_set_vars.config_value,
           value_len);
    *body_len = sizeof(fcfg_set_config_proto->env_len) +
                sizeof(fcfg_set_config_proto->name_len) +
                sizeof(fcfg_set_config_proto->value_len) +
                env_len +
                name_len +
                value_len;
}

int fcfg_admin_set_config ()
{
    int ret;
    char buff[1024];
    int body_len;
    int size;
    FCFGResponseInfo resp_info;
    FCFGProtoHeader *fcfg_header_proto;
    FCFGProtoSetConfigReq *fcfg_set_config_proto;

    fcfg_header_proto = (FCFGProtoHeader *)buff;
    fcfg_set_config_proto = (FCFGProtoSetConfigReq *)(buff + sizeof(FCFGProtoHeader));
    fcfg_set_admin_set_config(fcfg_set_config_proto, &body_len);
    fcfg_set_admin_header(fcfg_header_proto, FCFG_PROTO_SET_CONFIG_REQ, body_len);
    size = sizeof(FCFGProtoHeader) + body_len;
    ret = send_and_recv_response_header(&g_fcfg_admin_set_vars.join_conn, buff, size, &resp_info,
            g_fcfg_admin_set_vars.network_timeout, g_fcfg_admin_set_vars.connect_timeout);
    if (ret) {
        fprintf(stderr, "send_and_recv_response_header fail. ret:%d, %s\n",
                ret, strerror(ret));
        return ret;
    }
    ret = fcfg_admin_check_response(&g_fcfg_admin_set_vars.join_conn, &resp_info, g_fcfg_admin_set_vars.network_timeout);
    if (ret) {
        fprintf(stderr, "set config fail.err info: %s\n",
                resp_info.error.message);
    } else {
        fprintf(stderr, "set config success !\n");
    }

    return ret;
}

int fcfg_admin_set_load_config(const char *filename)
{
    IniContext ini_context;
    int result;
    char *pDataPath;

    memset(&ini_context, 0, sizeof(IniContext));
    if ((result=iniLoadFromFile(filename, &ini_context)) != 0) {
        fprintf(stderr, "file: "__FILE__", line: %d, "
                "load conf file \"%s\" fail, ret code: %d",
                __LINE__, filename, result);
        return result;
    }

    pDataPath = iniGetStrValue(NULL, "server_ip", &ini_context);
    if (pDataPath == NULL || *pDataPath == '\0') {
        fprintf(stderr, "get server_ip from file:%s", filename);
        return ENOENT;
    }
    snprintf(g_fcfg_admin_set_vars.join_conn.ip_addr, sizeof(g_fcfg_admin_set_vars.join_conn.ip_addr), "%s",
            pDataPath);
    g_fcfg_admin_set_vars.join_conn.port = iniGetIntValue(NULL, "server_port",
            &ini_context, 0);
    if (g_fcfg_admin_set_vars.join_conn.port == 0) {
        fprintf(stderr, "get server_port from file:%s", filename);
        return ENOENT;
    }

    g_fcfg_admin_set_vars.network_timeout = iniGetIntValue(NULL, "network_timeout",
            &ini_context, FCFG_NETWORK_TIMEOUT_DEFAULT);

    g_fcfg_admin_set_vars.connect_timeout = iniGetIntValue(NULL, "connect_timeout",
            &ini_context, FCFG_CONNECT_TIMEOUT_DEFAULT);

    if (g_fcfg_admin_set_vars.join_conn.port == 0) {
        fprintf(stderr, "get server_port from file:%s", filename);
        return ENOENT;
    }
    pDataPath = iniGetStrValue(NULL, "username", &ini_context);
    if (pDataPath == NULL || *pDataPath == '\0') {
        fprintf(stderr, "get username from file:%s", filename);
        return ENOENT;
    }
    snprintf(g_fcfg_admin_vars.username, sizeof(g_fcfg_admin_vars.username), "%s",
            pDataPath);

    pDataPath = iniGetStrValue(NULL, "secret_key", &ini_context);
    if (pDataPath == NULL || *pDataPath == '\0') {
        fprintf(stderr, "get secret_key from file:%s", filename);
        return ENOENT;
    }
    snprintf(g_fcfg_admin_vars.secret_key, sizeof(g_fcfg_admin_vars.secret_key), "%s",
            pDataPath);

    iniFreeContext(&ini_context);
    return 0;
}

int main (int argc, char **argv)
{
    int ret;

    if (argc < 5) {
        usage(argv[0]);
        return 1;
    }
    parse_args(argc, argv);
    if (show_usage) {
        usage(argv[0]);
        return 0;
    }

    ret = fcfg_admin_set_load_config(g_fcfg_admin_set_vars.config_file);
    if (ret) {
        fprintf(stderr, "fcfg_admin_set_load_config fail:%s, ret:%d, %s",
                g_fcfg_admin_set_vars.config_file, ret, strerror(ret));
        return ret;
    }


    if ((ret = conn_pool_connect_server(&g_fcfg_admin_set_vars.join_conn,
                g_fcfg_admin_set_vars.connect_timeout)) != 0) {
        return ret;
    }

    if ((ret = fcfg_send_admin_join_request(&g_fcfg_admin_set_vars.join_conn,
            g_fcfg_admin_set_vars.network_timeout,
            g_fcfg_admin_set_vars.connect_timeout)) != 0) {
        return ret;
    }

    ret = fcfg_admin_set_config();
    if (g_fcfg_admin_set_vars.join_conn.sock >= 0) {
        conn_pool_disconnect_server(&g_fcfg_admin_set_vars.join_conn);
    }
}

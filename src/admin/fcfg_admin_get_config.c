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

static bool show_usage = false;
FCFGAdminGetGlobal g_fcfg_admin_get_vars;
static void usage(char *program)
{
    fprintf(stderr, "Usage: %s options, the options as:\n"
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

void fcfg_set_admin_get_config(char *buff,
        int *body_len)
{
    FCFGProtoGetConfigReq *get_config_req = (FCFGProtoGetConfigReq *)buff;
    unsigned char env_len = strlen(g_fcfg_admin_get_vars.config_env);
    unsigned char name_len = strlen(g_fcfg_admin_get_vars.config_name);
    get_config_req->env_len = env_len;
    get_config_req->name_len = name_len;
    memcpy(get_config_req->env,
           g_fcfg_admin_get_vars.config_env,
           env_len);
    memcpy(get_config_req->env + env_len, g_fcfg_admin_get_vars.config_name,
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
        fprintf(stderr, "file: "__FILE__", line: %d, "
                "malloc %ld bytes fail", __LINE__, sizeof(FCFGConfigEntry));
        return ENOMEM;
    }

    ret = fcfg_admin_config_set_entry(get_config_resp, array->rows, &size);
    if (ret || (size != len)) {
        fprintf(stderr, "fcfg_admin_config_set_entry fail"
                " ret:%d, size:%d, len:%d", ret, size, len); 
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
        fprintf(stderr, "body_len is too long %d", resp_info->body_len);
        return -1;
    }
    ret = tcprecvdata_nb_ex(join_conn->sock, buff,
            resp_info->body_len, network_timeout, NULL);
    if (ret) {
        fprintf(stderr, "tcprecvdata_nb_ex fail %d", resp_info->body_len);
        return -1;
    }

    return fcfg_admin_extract_to_array(buff, resp_info->body_len, array);
}

int fcfg_admin_get_config (FCFGConfigArray *array, ConnectionInfo *join_conn)
{
    int ret;
    char buff[1024];
    int body_len;
    int size;
    FCFGResponseInfo resp_info;
    FCFGProtoHeader *fcfg_header_proto;

    fcfg_header_proto = (FCFGProtoHeader *)buff;
    fcfg_set_admin_get_config(buff + sizeof(FCFGProtoHeader), &body_len);
    fcfg_set_admin_header(fcfg_header_proto, FCFG_PROTO_GET_CONFIG_REQ, body_len);
    size = sizeof(FCFGProtoHeader) + body_len;
    ret = send_and_recv_response_header(join_conn, buff, size, &resp_info,
            g_fcfg_admin_vars.network_timeout, g_fcfg_admin_vars.connect_timeout);
    if (ret) {
        fprintf(stderr, "send_and_recv_response_header fail. ret:%d, %s\n",
                ret, strerror(ret));
        return ret;
    }
    ret = fcfg_admin_check_response(join_conn, &resp_info,
            g_fcfg_admin_vars.network_timeout, FCFG_PROTO_GET_CONFIG_RESP);
    if (ret) {
        fprintf(stderr, "get config fail.err info: %s\n",
                resp_info.error.message);
    } else {
        ret = fcfg_admin_get_config_response(join_conn, &resp_info,
                g_fcfg_admin_vars.network_timeout, array);
    }

    if (ret == 0) {
        fprintf(stderr, "get config success !\n");
    }
    return ret;
}

int fcfg_admin_config_get (int argc, char **argv)
{
    int ret;
    ConnectionInfo *join_conn = NULL;
    FCFGConfigArray array;

    if (argc < 7) {
        usage(argv[0]);
        return 1;
    }
    parse_args(argc, argv);
    if (show_usage) {
        usage(argv[0]);
        return 0;
    }

    log_init2();

    ret = fcfg_admin_load_config(g_fcfg_admin_get_vars.config_file);
    if (ret) {
        fprintf(stderr, "fcfg_admin_load_config fail:%s, ret:%d, %s\n",
                g_fcfg_admin_get_vars.config_file, ret, strerror(ret));
        goto END;
    }

    ret = fcfg_do_conn_config_server(&join_conn);
    if (ret) {
        goto END;
    }

    if ((ret = fcfg_send_admin_join_request(join_conn,
            g_fcfg_admin_vars.network_timeout,
            g_fcfg_admin_vars.connect_timeout)) != 0) {
        goto END;
    }

    ret = fcfg_admin_get_config(&array, join_conn);
    fcfg_admin_print_config_array(&array);

END:
    fcfg_disconn_config_server(join_conn);
    fcfg_free_config_array(&array);
    log_destroy();
    return ret;
}

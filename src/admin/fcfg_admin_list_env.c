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
#include "fcfg_admin_list_env.h"

static bool show_usage = false;
FCFGAdminListEnvGlobal g_fcfg_admin_list_env;
static void usage(char *program)
{
    fprintf(stderr, "Usage: %s options, the options as:\n"
            "\t -h help\n"
            "\t -c <config-filename>\n"
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
                g_fcfg_admin_list_env.config_file = optarg;
                break;
            case 'h':
            default:
                show_usage = true;
                break;
        }
    }
    if (found == 0 ||
        g_fcfg_admin_list_env.config_file == NULL) {
        show_usage = true;
    }
}

static int fcfg_admin_extract_to_array (char *buff, int len, FCFGEnvArray *array)
{
    int env_size;
    int size;
    int index;
    int ret;
    short count;
    FCFGProtoListEnvRespHeader *list_env_resp_header_proto;

    list_env_resp_header_proto = (FCFGProtoListEnvRespHeader *)buff;
    count = buff2short(list_env_resp_header_proto->count);

    array->rows = (FCFGEnvEntry *)malloc(sizeof(FCFGEnvEntry) * count);
    if (array->rows == NULL) {
        fprintf(stderr, "file: "__FILE__", line: %d, "
                "malloc %ld bytes fail", __LINE__, sizeof(FCFGEnvEntry));
        fcfg_free_env_array(array);
        return ENOMEM;
    }
    memset(array->rows, 0, sizeof(FCFGEnvEntry) * count);

    size = sizeof(FCFGProtoListEnvRespHeader);
    for (index = 0; index < count; index ++) {
        ret = fcfg_admin_env_set_entry(
                (FCFGProtoListEnvRespBodyPart *)(buff + size),
                array->rows + index,
                &env_size);
        if (ret) {
            break;
        }
        size += env_size;

        //fprintf(stderr, "size:%d, env_size:%d\n", size, env_size);
        array->count ++;
    }
    if (ret || (size != len)) {
        fprintf(stderr, "file: "__FILE__", line: %d, "
                "fcfg_admin_env_set_entry fail ret:%d, count:%d, size: %d, len: %d\n",
                __LINE__, ret, count, size, len);
        return -1;
    }

    return 0;
}

int fcfg_admin_list_env_response(ConnectionInfo *join_conn,
        FCFGResponseInfo *resp_info, int network_timeout, FCFGEnvArray *array)
{
    char buff[2048];
    int ret;
    if (resp_info->body_len == 0) {
        return -1;
    }
    if (resp_info->body_len > sizeof(buff)) {
        fprintf(stderr, "body_len is too long %d\n", resp_info->body_len);
        return -1;
    }
    ret = tcprecvdata_nb_ex(join_conn->sock, buff,
            resp_info->body_len, network_timeout, NULL);
    if (ret) {
        fprintf(stderr, "tcprecvdata_nb_ex fail %d\n", resp_info->body_len);
        return -1;
    }

    return fcfg_admin_extract_to_array(buff, resp_info->body_len, array);
}


int fcfg_admin_list_env (FCFGEnvArray *array, ConnectionInfo *join_conn)
{
    int ret;
    char buff[1024];
    int body_len;
    int size;
    FCFGResponseInfo resp_info;
    FCFGProtoHeader *fcfg_header_proto;
    fcfg_header_proto = (FCFGProtoHeader *)buff;
    body_len = 0;
    fcfg_set_admin_header(fcfg_header_proto, FCFG_PROTO_LIST_ENV_REQ, body_len);
    size = sizeof(FCFGProtoHeader) + body_len;
    ret = send_and_recv_response_header(join_conn, buff, size, &resp_info,
            g_fcfg_admin_vars.network_timeout, g_fcfg_admin_vars.connect_timeout);
    if (ret) {
        fprintf(stderr, "send_and_recv_response_header fail. ret:%d, %s\n",
                ret, strerror(ret));
        return ret;
    }
    ret = fcfg_admin_check_response(join_conn,
            &resp_info, g_fcfg_admin_vars.network_timeout, FCFG_PROTO_LIST_ENV_RESP);
    if (ret) {
        fprintf(stderr, "list env fail.err info: %s\n",
                resp_info.error.message);
    } else {
        ret = fcfg_admin_list_env_response(join_conn, &resp_info,
                g_fcfg_admin_vars.network_timeout, array);
        if (ret) {
            fprintf(stderr, "fcfg_admin_list_env_response fail\n");
        }
    }

    if (ret == 0) {
        fprintf(stderr, "list env success !\n");
    }
    return ret;
}

int fcfg_admin_env_list (int argc, char **argv)
{
    int ret;
    ConnectionInfo *join_conn = NULL;
    FCFGEnvArray array;
    memset(&array, 0, sizeof(FCFGEnvArray));

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }
    parse_args(argc, argv);
    if (show_usage) {
        usage(argv[0]);
        return 0;
    }

    log_init2();

    ret = fcfg_admin_load_config(g_fcfg_admin_list_env.config_file);
    if (ret) {
        fprintf(stderr, "fcfg_admin_load_config fail:%s, ret:%d, %s\n",
                g_fcfg_admin_list_env.config_file, ret, strerror(ret));
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

    ret = fcfg_admin_list_env(&array, join_conn);
    fcfg_admin_print_env_array(&array);

END:
    fcfg_disconn_config_server(join_conn);
    fcfg_free_env_array(&array);
    log_destroy();
    return ret;
}

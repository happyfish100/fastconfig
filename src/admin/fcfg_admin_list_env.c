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

/*
static bool show_usage = false;
static void usage(char *program)
{
    logInfo("file: "__FILE__", line: %d""Usage: %s options, the options as:\n"
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
*/

static int fcfg_admin_extract_to_array (char *buff, int len, FCFGEnvArray *array)
{
    int env_size;
    int size;
    int index;
    int ret = 0;
    short count;
    FCFGProtoListEnvRespHeader *list_env_resp_header_proto;

    list_env_resp_header_proto = (FCFGProtoListEnvRespHeader *)buff;
    count = buff2short(list_env_resp_header_proto->count);

    array->rows = (FCFGEnvEntry *)malloc(sizeof(FCFGEnvEntry) * count);
    if (array->rows == NULL) {
        logInfo("file: "__FILE__", line: %d, "
                "malloc %ld bytes fail", __LINE__, sizeof(FCFGEnvEntry));
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

        array->count ++;
    }
    if (ret || (size != len)) {
        logInfo("file: "__FILE__", line: %d, "
                "fcfg_admin_extract_to_array fail ret:%d, count:%d, size: %d, len: %d\n",
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
        return 0;
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


int fcfg_admin_list_env (struct fcfg_context *fcfg_context, FCFGEnvArray *array)
{
    int ret;
    char buff[1024];
    int body_len;
    int size;
    FCFGResponseInfo resp_info;
    FCFGProtoHeader *fcfg_header_proto;
    ConnectionInfo *join_conn;
    fcfg_header_proto = (FCFGProtoHeader *)buff;

    join_conn = fcfg_context->join_conn + fcfg_context->join_index;
    body_len = 0;
    fcfg_set_admin_header(fcfg_header_proto, FCFG_PROTO_LIST_ENV_REQ, body_len);
    size = sizeof(FCFGProtoHeader) + body_len;
    ret = send_and_recv_response_header(join_conn, buff, size, &resp_info,
            fcfg_context->network_timeout, fcfg_context->connect_timeout);
    if (ret) {
        logInfo("file: "__FILE__", line: %d"
                "send_and_recv_response_header fail. ret:%d, %s",
                __LINE__,
                ret, strerror(ret));
        return ret;
    }
    ret = fcfg_admin_check_response(join_conn,
            &resp_info, fcfg_context->network_timeout, FCFG_PROTO_LIST_ENV_RESP);
    if (ret) {
        logInfo("file: "__FILE__", line: %d, "
                "list env fail.err info: %s",
                __LINE__,
                resp_info.error.message);
    } else {
        ret = fcfg_admin_list_env_response(join_conn, &resp_info,
                fcfg_context->network_timeout, array);
        if (ret) {
            logInfo("file: "__FILE__", line: %d, "
                    "fcfg_admin_list_env_response fail", __LINE__);
        }
    }

    if (ret == 0) {
        logInfo("file: "__FILE__", line: %d, "
                "list env success !", __LINE__);
    }
    return ret;
}

int fcfg_admin_env_list (struct fcfg_context *fcfg_context,
        FCFGEnvArray *array)
{
    int ret;
    memset(array, 0, sizeof(FCFGEnvArray));

    if ((ret = fcfg_send_admin_join_request(fcfg_context,
            fcfg_context->network_timeout,
            fcfg_context->connect_timeout)) != 0) {
        return ret;
    }

    ret = fcfg_admin_list_env(fcfg_context, array);
    return ret;
}

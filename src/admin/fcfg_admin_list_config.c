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
#include "fcfg_admin_list_config.h"

static bool show_usage = false;
FCFGAdminListConfigGlobal g_fcfg_admin_list_config;
static void usage(char *program)
{
    fprintf(stderr, "Usage: %s options, the options as:\n"
            "\t -h help\n"
            "\t -c <config-filename>\n"
            "\t -e <config-env>\n"
            "\t -n <config-name>\n"
            "\t -l <limit>\n"
            "\n", program);
}

static void parse_args(int argc, char **argv)
{
    int ch;
    int found = 0;

    while ((ch = getopt(argc, argv, "hc:e:n:l:")) != -1) {
        found = 1;
        switch (ch) {
            case 'c':
                g_fcfg_admin_list_config.config_file = optarg;
                break;
            case 'e':
                g_fcfg_admin_list_config.config_env = optarg;
                break;
            case 'n':
                g_fcfg_admin_list_config.config_name = optarg;
                break;
            case 'l':
                g_fcfg_admin_list_config.limit = atoi(optarg);
                break;
            case 'h':
            default:
                show_usage = true;
                break;
        }
    }
    if (found == 0) {
        show_usage = true;
    }
}

void fcfg_set_admin_list_config(char *buff,
        int *body_len, int offset, int count)
{
    FCFGProtoListConfigReq *list_config_req = (FCFGProtoListConfigReq *)buff;
    unsigned char env_len = strlen(g_fcfg_admin_list_config.config_env);
    unsigned char name_len = 0;

    if (g_fcfg_admin_list_config.config_name) {
        name_len = strlen(g_fcfg_admin_list_config.config_name);
    }

    list_config_req->env_len = env_len;
    list_config_req->name_len = name_len;
    short2buff(offset, list_config_req->limit.offset);
    short2buff(count, list_config_req->limit.count);

    memcpy(list_config_req->env, g_fcfg_admin_list_config.config_env,
           env_len);
    if (name_len) {
        memcpy(list_config_req->env + env_len,
                g_fcfg_admin_list_config.config_name,
                name_len);
    }

    *body_len = env_len + name_len + sizeof(FCFGProtoListConfigReq);
}

int fcfg_admin_extract_to_array (char *buff, int len, FCFGConfigArray *array)
{
    int size;
    int config_size;
    int index;
    short count;
    int ret;
    FCFGProtoListConfigRespBodyPart *list_config_resp_body_proto;
    FCFGProtoListConfigRespHeader *list_config_resp_header_proto =
        (FCFGProtoListConfigRespHeader *)buff;
    count = buff2short(list_config_resp_header_proto->count);
    if (count <= 0) {
        fprintf(stderr, "list config response count %d\n", count);
        return 0;
    }

    list_config_resp_body_proto =
        (FCFGProtoListConfigRespBodyPart *)(list_config_resp_header_proto + 1);
    array->rows = (FCFGConfigEntry *)malloc(sizeof(FCFGConfigEntry) * count);
    if (array->rows == NULL) {
        fprintf(stderr, "file: "__FILE__", line: %d, "
                "malloc %ld bytes fail", __LINE__, sizeof(FCFGConfigEntry));
        return ENOMEM;
    }
    memset(array->rows, 0, sizeof(FCFGConfigEntry) * count);

    size = sizeof(FCFGProtoListConfigRespHeader);
    for (index = 0; index < count; index ++) {
        ret = fcfg_admin_config_set_entry((FCFGProtoListConfigRespBodyPart *)(buff + size),
                array->rows + index, &config_size);
        if (ret) {
            break;
        }
        size += config_size;
        array->count ++;
    }
    if (ret || (size != len)) {
        fprintf(stderr, "fcfg_admin_config_set_entry fail"
                " ret:%d, count:%d, size:%d, len:%d", ret, count, size, len);
        return -1;
    }

    return 0;
}

int fcfg_admin_list_config_response(ConnectionInfo *join_conn,
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


int fcfg_admin_list_config (FCFGConfigArray *array, ConnectionInfo *join_conn)
{
    int ret;
    char buff[1024];
    int body_len;
    int size;
    int offset;
    int i;
    int count;
    FCFGResponseInfo resp_info;
    FCFGProtoHeader *fcfg_header_proto;

    count = FCFG_ADMIN_LIST_REQUEST_COUNT;
    offset = g_fcfg_admin_list_config.limit / FCFG_ADMIN_LIST_REQUEST_COUNT + 1;
    if (g_fcfg_admin_list_config.limit < FCFG_ADMIN_LIST_REQUEST_COUNT) {
        offset = 1;
        count = g_fcfg_admin_list_config.limit;
    }
    for (i = 0; i < offset; i ++) {
        fcfg_header_proto = (FCFGProtoHeader *)buff;
        fcfg_set_admin_list_config(buff + sizeof(FCFGProtoHeader), &body_len,
                i, count);
        fcfg_set_admin_header(fcfg_header_proto, FCFG_PROTO_LIST_CONFIG_REQ, body_len);
        size = sizeof(FCFGProtoHeader) + body_len;
        ret = send_and_recv_response_header(join_conn, buff, size, &resp_info,
                g_fcfg_admin_vars.network_timeout, g_fcfg_admin_vars.connect_timeout);
        if (ret) {
            fprintf(stderr, "send_and_recv_response_header fail. ret:%d, %s\n",
                    ret, strerror(ret));
            return ret;
        }
        ret = fcfg_admin_check_response(join_conn,
                &resp_info, g_fcfg_admin_vars.network_timeout,
                FCFG_PROTO_LIST_CONFIG_RESP);
        if (ret) {
            fprintf(stderr, "list config fail.err info: %*.s\n",
                    resp_info.body_len, resp_info.error.message);
            break;
        } else {
            ret = fcfg_admin_list_config_response(join_conn, &resp_info,
                    g_fcfg_admin_vars.network_timeout, array);
            if (ret) {
                fprintf(stderr, "fcfg_admin_list_config_response fail\n");
                break;
            }
        }
    }

    if (ret == 0) {
        fprintf(stderr, "get config success !\n");
    }
    return ret;
}

int main (int argc, char **argv)
{
    int ret;
    ConnectionInfo *join_conn = NULL;
    FCFGConfigArray array;
    memset(&array, 0, sizeof(FCFGConfigArray));
    memset(&g_fcfg_admin_list_config, 0,
            sizeof(FCFGAdminListConfigGlobal));

    if (argc < 7) {
        usage(argv[0]);
        return 1;
    }
    parse_args(argc, argv);
    if (show_usage) {
        usage(argv[0]);
        return 0;
    }

    if (g_fcfg_admin_list_config.limit == 0) {
        fprintf(stderr, "limit is 0 !\n");
        return 0;
    }
    log_init2();

    ret = fcfg_admin_load_config(g_fcfg_admin_list_config.config_file);
    if (ret) {
        fprintf(stderr, "fcfg_admin_load_config fail:%s, ret:%d, %s\n",
                g_fcfg_admin_list_config.config_file, ret, strerror(ret));
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

    ret = fcfg_admin_list_config(&array, join_conn);
    fcfg_admin_print_config_array(&array);

END:
    fcfg_disconn_config_server(join_conn);
    fcfg_free_config_array(&array);
    log_destroy();
    return 0;
}

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
FCFGAdminListConfigGlobal g_fcfg_admin_list_vars;
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
                g_fcfg_admin_list_vars.config_file = optarg;
                break;
            case 'e':
                g_fcfg_admin_list_vars.config_env = optarg;
                break;
            case 'n':
                g_fcfg_admin_list_vars.config_name = optarg;
                break;
            case 'l':
                g_fcfg_admin_list_vars.limit = atoi(optarg);
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
    int index;
    unsigned char env_len = strlen(g_fcfg_admin_list_vars.config_env);
    unsigned char name_len = 0;
    if (g_fcfg_admin_list_vars.config_name) {
        name_len = strlen(g_fcfg_admin_list_vars.config_name);
    }

    index = 0;
    *(buff + index) = env_len;
    index += 1;
    *(buff + index) = name_len;
    index += 1;
    short2buff(offset, buff + index);
    index += 2;
    short2buff(count, buff + index);
    index += 2;

    if (name_len) {
        memcpy(buff + index,
                g_fcfg_admin_list_vars.config_name,
                name_len);
        index += name_len;
    }
    memcpy(buff + index, g_fcfg_admin_list_vars.config_env,
           env_len);
    index += env_len;

    *body_len = index;
}

int fcfg_admin_extract_to_array (char *buff, int len, FCFGConfigArray *array)
{
    int size;
    int index;
    FCFGConfigEntry *rows;

    index = 0;
    rows = array->rows + array->count;
    while (index < len) {
        rows->status = *(buff + index);
        index += 1;
        rows->name.len = *(buff + index);
        index += 1;
        rows->value.len = buff2int(buff + index);
        index += 4;
        rows->version = buff2long(buff + index); 
        index += 8;
        rows->create_time = buff2int(buff + index);
        index += 4;
        rows->update_time = buff2int(buff + index);
        index += 4;

        size = rows->name.len + rows->value.len;
        rows->name.str = (char *)malloc(size + 2);
        if (rows->name.str == NULL) {
            fprintf(stderr, "file: "__FILE__", line: %d, "
                    "malloc %d bytes fail", __LINE__, size + 2);
            fcfg_free_config_array(array);
            return ENOMEM;
        }
        memset(rows->name.str, 0, size + 2);
        memcpy(rows->name.str, buff + index, rows->name.len + 1);
        index += rows->name.len + 1;
        rows->value.str =  rows->name.str + rows->name.len + 1;
        memcpy(rows->value.str, buff + index, rows->value.len + 1);
        index += rows->value.len + 1;
        array->count ++;
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
    FCFGResponseInfo resp_info;
    FCFGProtoHeader *fcfg_header_proto;

    array->rows = (FCFGConfigEntry *)malloc(sizeof(FCFGConfigEntry) * g_fcfg_admin_list_vars.limit);
    if (array->rows == NULL) {
        fprintf(stderr, "file: "__FILE__", line: %d, "
                "malloc %ld bytes fail", __LINE__, sizeof(FCFGConfigEntry));
        fcfg_free_config_array(array);
        return ENOMEM;
    }
    memset(array->rows, 0, sizeof(FCFGConfigEntry) * g_fcfg_admin_list_vars.limit);

    offset = g_fcfg_admin_list_vars.limit / FCFG_ADMIN_LIST_REQUEST_COUNT + 1;
    for (i = 0; i < offset; i ++) {
        fcfg_header_proto = (FCFGProtoHeader *)buff;
        fcfg_set_admin_list_config(buff + sizeof(FCFGProtoHeader), &body_len,
                i, FCFG_ADMIN_LIST_REQUEST_COUNT);
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
                &resp_info, g_fcfg_admin_vars.network_timeout, FCFG_PROTO_LIST_ENV_RESP);
        if (ret) {
            fprintf(stderr, "list config fail.err info: %s\n",
                    resp_info.error.message);
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
    ConnectionInfo *join_conn;
    FCFGConfigArray array;
    memset(&array, 0, sizeof(FCFGConfigArray));

    if (argc < 7) {
        usage(argv[0]);
        return 1;
    }
    parse_args(argc, argv);
    if (show_usage) {
        usage(argv[0]);
        return 0;
    }

    if (g_fcfg_admin_list_vars.limit == 0) {
        fprintf(stderr, "limit is 0 !\n");
        return 0;
    }
    log_init2();

    ret = fcfg_admin_load_config(g_fcfg_admin_list_vars.config_file);
    if (ret) {
        fprintf(stderr, "fcfg_admin_load_config fail:%s, ret:%d, %s\n",
                g_fcfg_admin_list_vars.config_file, ret, strerror(ret));
        log_destroy();
        return ret;
    }

    ret = fcfg_do_conn_config_server(&join_conn);
    if (ret) {
        log_destroy();
        return ret;
    }

    if ((ret = fcfg_send_admin_join_request(join_conn,
            g_fcfg_admin_vars.network_timeout,
            g_fcfg_admin_vars.connect_timeout)) != 0) {
        log_destroy();
        return ret;
    }

    ret = fcfg_admin_list_config(&array, join_conn);
    fcfg_disconn_config_server(join_conn);
    log_destroy();
    return 0;
}

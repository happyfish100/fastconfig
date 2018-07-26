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
    if (found == 0) {
        show_usage = true;
    }
}

void fcfg_set_admin_get_config(char *buff,
        int *body_len)
{
    unsigned char env_len = strlen(g_fcfg_admin_get_vars.config_env);
    unsigned char name_len = strlen(g_fcfg_admin_get_vars.config_name);
    *buff = env_len;
    *(buff + 1) = name_len;
    memcpy(buff + 2,
           g_fcfg_admin_get_vars.config_name,
           name_len);
    memcpy(buff + 2 + name_len, g_fcfg_admin_get_vars.config_env,
           env_len);
    *body_len = 2 + env_len + name_len;
}

int fcfg_admin_extract_to_array (char *buff, int len, FCFGConfigArray *array)
{
    int size;
    int offset;
    int value_offset = offset_of_member(FCFGProtoPushConfigBodyPart, value);
    //int value_offset = ((int)(&(((FCFGProtoPushConfigBodyPart *)0)->value)));

    array->count = 1;
    array->rows = (FCFGConfigEntry *)malloc(sizeof(FCFGConfigEntry));
    if (array->rows == NULL) {
        fprintf(stderr, "file: "__FILE__", line: %d, "
                "malloc %ld bytes fail", __LINE__, sizeof(FCFGConfigEntry));
        fcfg_free_config_array(array);
        return ENOMEM;
    }

    offset = 0;
    array->rows->status = *(buff + offset);
    offset += 1;
    array->rows->name.len = *(buff + offset);
    offset += 1;
    array->rows->value.len = buff2int(buff + offset);
    offset += 4;
    array->rows->version = buff2long(buff + offset); 
    offset += 8;
    array->rows->create_time = buff2int(buff + offset);
    offset += 4;
    array->rows->update_time = buff2int(buff + offset);
    offset += 4;

    size = array->rows->name.len + array->rows->value.len;
    if ((size + value_offset) != len) {
        fprintf(stderr, "fcfg_admin_extract_to_array len err: %d:%d",
                size + value_offset, len);
        return -1;
    }
    array->rows->name.str = (char *)malloc(size + 2);
    if (array->rows->name.str == NULL) {
        fprintf(stderr, "file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, size + 2);
        fcfg_free_config_array(array);
        return ENOMEM;
    }
    memcpy(array->rows->name.str, buff + offset, array->rows->name.len + 1);
    offset += array->rows->name.len + 1;
    array->rows->value.str =  array->rows->name.str + array->rows->name.len + 1;
    memcpy(array->rows->value.str, buff + offset, array->rows->value.len + 1);
    offset += array->rows->value.len + 1;

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


int fcfg_admin_get_config (FCFGConfigArray *array)
{
    int ret;
    char buff[1024];
    int body_len;
    int size;
    FCFGResponseInfo resp_info;
    FCFGProtoHeader *fcfg_header_proto;

    fcfg_header_proto = (FCFGProtoHeader *)buff;
    fcfg_set_admin_get_config(buff + sizeof(FCFGProtoHeader), &body_len);
    fcfg_set_admin_header(fcfg_header_proto, FCFG_PROTO_DEL_CONFIG_REQ, body_len);
    size = sizeof(FCFGProtoHeader) + body_len;
    ret = send_and_recv_response_header(&g_fcfg_admin_vars.join_conn, buff, size, &resp_info,
            g_fcfg_admin_vars.network_timeout, g_fcfg_admin_vars.connect_timeout);
    if (ret) {
        fprintf(stderr, "send_and_recv_response_header fail. ret:%d, %s\n",
                ret, strerror(ret));
        return ret;
    }
    ret = fcfg_admin_check_response(&g_fcfg_admin_vars.join_conn, &resp_info, g_fcfg_admin_vars.network_timeout);
    if (ret) {
        fprintf(stderr, "get config fail.err info: %s\n",
                resp_info.error.message);
    } else {
        ret = fcfg_admin_get_config_response(&g_fcfg_admin_vars.join_conn, &resp_info,
                g_fcfg_admin_vars.network_timeout, array);
    }

    if (ret == 0) {
        fprintf(stderr, "get config success !\n");
    }
    return ret;
}

int main (int argc, char **argv)
{
    int ret;
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
        log_destroy();
        return ret;
    }


    if ((ret = conn_pool_connect_server(&g_fcfg_admin_vars.join_conn,
                    g_fcfg_admin_vars.connect_timeout)) != 0) {
        fprintf(stderr, "conn_pool_connect_server fail: %s:%d, ret:%d, %s\n",
                g_fcfg_admin_vars.join_conn.ip_addr,
                g_fcfg_admin_vars.join_conn.port,
                ret, strerror(ret));
        log_destroy();
        return ret;
    }

    if ((ret = fcfg_send_admin_join_request(&g_fcfg_admin_vars.join_conn,
            g_fcfg_admin_vars.network_timeout,
            g_fcfg_admin_vars.connect_timeout)) != 0) {
        log_destroy();
        return ret;
    }

    ret = fcfg_admin_get_config(&array);
    if (g_fcfg_admin_vars.join_conn.sock >= 0) {
        conn_pool_disconnect_server(&g_fcfg_admin_vars.join_conn);
    }

    log_destroy();
    return 0;
}

#include "common/fcfg_proto.h"
#include "fcfg_admin_func.h"
#include "fastcommon/sockopt.h"

FCFGAdminGlobal g_fcfg_admin_vars;
void fcfg_set_admin_join_req(char *buff,
        int *body_len)
{
    unsigned char username_len = strlen(g_fcfg_admin_vars.username);
    unsigned char secret_key_len = strlen(g_fcfg_admin_vars.secret_key);
    *buff = username_len;
    *(buff + 1) = secret_key_len;
    memcpy(buff + 2, g_fcfg_admin_vars.secret_key,
           secret_key_len);
    memcpy(buff + 2  + secret_key_len,
            g_fcfg_admin_vars.username,
            username_len);
    *body_len = 1 + 1 + secret_key_len + username_len;
}

int send_and_recv_response_header(ConnectionInfo *conn, char *data, int len,
        FCFGResponseInfo *resp_info, int network_timeout, int connect_timeout)
{
    int ret;
    FCFGProtoHeader fcfg_header_resp_pro;

    if ((ret = tcprecvdata_nb_ex(conn->sock, data,
            len, network_timeout, NULL)) != 0) {
        return ret;
    }
    if ((ret = tcprecvdata_nb_ex(conn->sock, &fcfg_header_resp_pro,
            sizeof(FCFGProtoHeader), network_timeout, NULL)) != 0) {
        return ret;
    }
    fcfg_proto_response_extract(&fcfg_header_resp_pro, resp_info);
    return 0;
}

int fcfg_admin_load_config(const char *filename)
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
    snprintf(g_fcfg_admin_vars.join_conn.ip_addr, sizeof(g_fcfg_admin_vars.join_conn.ip_addr), "%s",
            pDataPath);
    g_fcfg_admin_vars.join_conn.port = iniGetIntValue(NULL, "server_port",
            &ini_context, 0);
    if (g_fcfg_admin_vars.join_conn.port == 0) {
        fprintf(stderr, "get server_port from file:%s", filename);
        return ENOENT;
    }

    g_fcfg_admin_vars.network_timeout = iniGetIntValue(NULL, "network_timeout",
            &ini_context, FCFG_NETWORK_TIMEOUT_DEFAULT);

    g_fcfg_admin_vars.connect_timeout = iniGetIntValue(NULL, "connect_timeout",
            &ini_context, FCFG_CONNECT_TIMEOUT_DEFAULT);

    if (g_fcfg_admin_vars.join_conn.port == 0) {
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


int fcfg_admin_check_response(ConnectionInfo *join_conn,
        FCFGResponseInfo *resp_info, int network_timeout, unsigned char resp_cmd)
{
    if (resp_info->cmd == resp_cmd && resp_info->status == 0) {
        return 0;
    } else {
        if (resp_info->body_len) {
            tcprecvdata_nb_ex(join_conn->sock, resp_info->error.message,
                    resp_info->body_len, network_timeout, NULL);
        } else {
            resp_info->error.message[0] = '\0';
        }
        return 1;
    }

}
int fcfg_send_admin_join_request(ConnectionInfo *join_conn, int network_timeout,
        int connect_timeout)
{
    int ret;
    char buff[1024];
    int body_len;
    int size;
    FCFGResponseInfo resp_info;
    FCFGProtoHeader *fcfg_header_proto;

    fcfg_header_proto = (FCFGProtoHeader *)buff;
    fcfg_set_admin_join_req(buff + sizeof(FCFGProtoHeader), &body_len);
    fcfg_set_admin_header(fcfg_header_proto, FCFG_PROTO_ADMIN_JOIN_REQ, body_len);
    size = sizeof(FCFGProtoHeader) + body_len;
    ret = send_and_recv_response_header(join_conn, buff, size, &resp_info,
            network_timeout, connect_timeout);
    if (ret) {
        fprintf(stderr, "send_and_recv_response_header fail. ret:%d, %s\n",
                ret, strerror(ret));
        return ret;
    }
    ret = fcfg_admin_check_response (join_conn, &resp_info, network_timeout, FCFG_PROTO_ACK);
    if (ret) {
        fprintf(stderr, "join server fail. %s\n", resp_info.error.message);
    } else {
        fprintf(stderr, "join server success!\n");
    }

    return ret;
}

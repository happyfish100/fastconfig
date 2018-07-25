#include "common/fcfg_proto.h"
#include "fcfg_admin_func.h"
#include "fastcommon/sockopt.h"

FCFGAdminGlobal g_fcfg_admin_vars;
void fcfg_set_admin_join_req(FCFGProtoAdminJoinReq *fcfg_admin_join_req_proto,
        int *body_len)
{
    fcfg_admin_join_req_proto->username_len =
        strlen(g_fcfg_admin_vars.username);
    fcfg_admin_join_req_proto->secret_key_len =
        strlen(g_fcfg_admin_vars.secret_key);
    memcpy(fcfg_admin_join_req_proto->secret_key, g_fcfg_admin_vars.secret_key,
            fcfg_admin_join_req_proto->secret_key_len);
    memcpy(fcfg_admin_join_req_proto->secret_key + fcfg_admin_join_req_proto->secret_key_len,
            g_fcfg_admin_vars.username,
            fcfg_admin_join_req_proto->username_len);
    *body_len = sizeof (fcfg_admin_join_req_proto->username_len) +
               sizeof (fcfg_admin_join_req_proto->secret_key_len) +
               fcfg_admin_join_req_proto->secret_key_len +
               fcfg_admin_join_req_proto->username_len;
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

int fcfg_admin_check_response(ConnectionInfo *join_conn,
        FCFGResponseInfo *resp_info, int network_timeout)
{
    if (resp_info->cmd == FCFG_PROTO_ACK && resp_info->status == 0) {
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
    FCFGProtoAdminJoinReq *fcfg_admin_join_req_proto;
    FCFGProtoHeader *fcfg_header_proto;

    fcfg_header_proto = (FCFGProtoHeader *)buff;
    fcfg_admin_join_req_proto = (FCFGProtoAdminJoinReq *)(buff + sizeof(FCFGProtoHeader));
    fcfg_set_admin_join_req(fcfg_admin_join_req_proto, &body_len);
    fcfg_set_admin_header(fcfg_header_proto, FCFG_PROTO_ADMIN_JOIN_REQ, body_len);
    size = sizeof(FCFGProtoHeader) + body_len;
    ret = send_and_recv_response_header(join_conn, buff, size, &resp_info,
            network_timeout, connect_timeout);
    if (ret) {
        fprintf(stderr, "send_and_recv_response_header fail. ret:%d, %s\n",
                ret, strerror(ret));
        return ret;
    }
    ret = fcfg_admin_check_response (join_conn, &resp_info, network_timeout);
    if (ret) {
        fprintf(stderr, "join server fail. %s\n", resp_info.error.message);
    } else {
        fprintf(stderr, "join server success!\n");
    }

    return ret;
}

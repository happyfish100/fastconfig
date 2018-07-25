
#include <errno.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/connection_pool.h"
#include "fastcommon/ini_file_reader.h"
#include "fcfg_proto.h"
#include "fcfg_types.h"

void fcfg_proto_init()
{
}

int fcfg_proto_set_body_length(struct fast_task_info *task)
{
    task->length = buff2int(((FCFGProtoHeader *)task->data)->body_len);
    return 0;
}

int fcfg_proto_deal_actvie_test(struct fast_task_info *task,
        const FCFGRequestInfo *request, FCFGResponseInfo *response)
{
    return FCFG_PROTO_EXPECT_BODY_LEN(task, request, response, 0);
}

int send_and_recv_response_header(ConnectionInfo *conn, char *data, int len,
        FCFGResponseInfo *resp_info, int network_timeout, int connect_timeout)
{
    int ret;
    FCFGProtoHeader fcfg_header_resp_pro;

    if (ret = tcprecvdata_nb_ex(conn->sock, data,
            len, network_timeout, NULL) != 0) {
        return ret;
    }
    if (ret = tcprecvdata_nb_ex(conn->sock, &fcfg_header_resp_pro,
            sizeof(FCFGProtoHeader), network_timeout, NULL) != ) {
        return ret;
    }
    return fcfg_proto_response_extract(&fcfg_header_resp_pro, resp_info);
}


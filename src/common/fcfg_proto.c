
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

int fcfg_proto_set_join_req(char *buff, char *env, int64_t version)
{
    FCFGProtoHeader *fcfg_header_pro;
    FCFGProtoJoinReq *fcfg_join_req_pro;

    fcfg_header_pro = (FCFGProtoHeader *)buff;
    fcfg_header_pro->cmd = FCFG_PROTO_JION_REQ;
    int2buff(sizeof(FCFGProtoJoinReq), fcfg_header_pro->body_len);

    fcfg_join_req_pro = (FCFGProtoJoinReq *)(buff + sizeof(FCFGProtoHeader));
    strncpy(fcfg_join_req_pro->env, env, sizeof(fcfg_join_req_pro->env));
    long2buff(version, fcfg_join_req_pro->agent_cfg_version);

    return 0;
}

int fcfg_extract_join_resp(FCFGJoinResp *join_resp_data,
        FCFGProtoJoinResp *join_resp_pro)
{
    join_resp_data->center_cfg_version = buff2long(join_resp_pro->center_cfg_version);

    return 0;
}

int fcfg_extract_push_config_header(
        FCFGProtoPushConfigHeader *fcfg_push_header_pro,
        FCFGPushConfigHeader *fcfg_push_header)
{
    fcfg_push_header->count = buff2short(fcfg_push_header_pro->count);

    return 0;
}

int fcfg_check_push_config_body_len(FCFGPushConfigHeader *fcfg_push_header,
        FCFGProtoPushConfigBodyPart *fcfg_push_body_pro, int len)
{
    int i;
    int size;
    unsigned char name_len;
    int value_len;
    int body_part_len = 0;
    int count = fcfg_push_header->count;

    size = sizeof(FCFGPushConfigBodyPart);
    for (i = 0; i < count; i ++) {
        name_len = fcfg_push_body_pro->name_len;
        value_len = buff2int(fcfg_push_body_pro->value_len);
        body_part_len += size + name_len + value_len;;
        if (body_part_len > len) {
            return -1;
        }
    }

    if (body_part_len != len) {
        return -1;
    }

    return 0;
}

int fcfg_extract_push_config_body_data (
        FCFGProtoPushConfigBodyPart *fcfg_push_body_pro,
        FCFGPushConfigBodyPart *fcfg_push_body_data)
{
    fcfg_push_body_data->status = fcfg_push_body_pro->status;
    fcfg_push_body_data->name_len = fcfg_push_body_pro->name_len;
    fcfg_push_body_data->value_len = buff2int(fcfg_push_body_pro->value_len);
    fcfg_push_body_data->version = buff2long(fcfg_push_body_pro->version);

    return 0;
}
void fcfg_proto_response_extract (FCFGProtoHeader *header_pro,
        FCFGResponseInfo *resp_info)
{
    resp_info->cmd      = header_pro->cmd;
    resp_info->body_len = buff2int(header_pro->body_len);
    resp_info->status   = header_pro->status;
}

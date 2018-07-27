
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

void fcfg_proto_response_extract (FCFGProtoHeader *header_pro,
        FCFGResponseInfo *resp_info)
{
    resp_info->cmd      = header_pro->cmd;
    resp_info->body_len = buff2int(header_pro->body_len);
    resp_info->status   = header_pro->status;
}

void fcfg_set_admin_header (FCFGProtoHeader *fcfg_header_proto,
        unsigned char cmd, int body_len)
{
    fcfg_header_proto->cmd = cmd;
    int2buff(body_len, fcfg_header_proto->body_len);
}

void fcfg_free_config_array(FCFGConfigArray *array)
{
    FCFGConfigEntry *current;
    FCFGConfigEntry *end;

    if (array->rows == NULL) {
        return;
    }

    end = array->rows + array->count;
    for (current=array->rows; current<end; current++) {
        if (current->name.str != NULL) {
            free(current->name.str);
        }
    }

    free(array->rows);
    array->rows = NULL;
    array->count = 0;
}

void fcfg_free_env_array(FCFGEnvArray *array)
{
    FCFGEnvEntry *current;
    FCFGEnvEntry *end;

    if (array->rows == NULL) {
        return;
    }

    end = array->rows + array->count;
    for (current=array->rows; current<end; current++) {
        if (current->env.str != NULL) {
            free(current->env.str);
        }
    }

    free(array->rows);
    array->rows = NULL;
    array->count = 0;
}

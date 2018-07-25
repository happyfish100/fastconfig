
#include <sys/stat.h>
#include "fastcommon/ini_file_reader.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "sf/sf_global.h"
#include "sf/sf_service.h"
#include "sf/sf_util.h"
#include "common/fcfg_types.h"
#include "common/fcfg_proto.h"
#include "fcfg_agent_global.h"
#include "fcfg_agent_func.h"

int fcfg_agent_load_config(const char *filename)
{
    IniContext ini_context;
    int result;
    char *pDataPath;

    memset(&ini_context, 0, sizeof(IniContext));
    if ((result=iniLoadFromFile(filename, &ini_context)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "load conf file \"%s\" fail, ret code: %d",
                __LINE__, filename, result);
        return result;
    }

    if ((result=sf_load_config("fcfg_agentd", filename, &ini_context,
                    FCFG_SERVER_DEFAULT_INNER_PORT,
                    FCFG_SERVER_DEFAULT_OUTER_PORT)) != 0)
    {
        return result;
    }

    pDataPath = iniGetStrValue(NULL, "shm_config_file", &ini_context);
    if (pDataPath == NULL || *pDataPath == '\0') {
        lerr("get shm_config_file from file:%s", filename);
        return ENOENT;
    }
    snprintf(g_agent_global_vars.shm_config_file, MAX_PATH_SIZE, "%s",
             pDataPath);

    pDataPath = iniGetStrValue(NULL, "server_ip", &ini_context);
    if (pDataPath == NULL || *pDataPath == '\0') {
        lerr("get server_ip from file:%s", filename);
        return ENOENT;
    }
    snprintf(g_agent_global_vars.join_conn.ip_addr, sizeof(g_agent_global_vars.join_conn.ip_addr), "%s",
             pDataPath);
    g_agent_global_vars.join_conn.port = iniGetIntValue(NULL, "server_port",
            &ini_context, 0);
    if (g_agent_global_vars.join_conn.port == 0) {
        lerr("get server_port from file:%s", filename);
        return ENOENT;
    }
    g_agent_global_vars.join_conn.sock = -1;

    pDataPath = iniGetStrValue(NULL, "config_env", &ini_context);
    if (pDataPath == NULL || *pDataPath == '\0') {
        lerr("get config_env from file:%s", filename);
        return ENOENT;
    }
    snprintf(g_agent_global_vars.env, sizeof(g_agent_global_vars.env), "%s",
            pDataPath);
    snprintf(g_agent_global_vars.shm_version_key, sizeof(g_agent_global_vars.shm_version_key),
             "%s_%s", g_agent_global_vars.env, FCFG_AGENT_SHM_VERSION_KEY_SUFFIX);

    iniFreeContext(&ini_context);

    linfo("base_path: %s, "
          "shm_config_file: %s, "
          "env: %s, "
          "shm_version_key: %s, "
          "server_ip:%s, "
          "server_port:%d",
          g_sf_global_vars.base_path,
          g_agent_global_vars.shm_config_file,
          g_agent_global_vars.env,
          g_agent_global_vars.shm_version_key,
          g_agent_global_vars.join_conn.ip_addr,
          g_agent_global_vars.join_conn.port);

    sf_log_config_ex(NULL);
    return 0;
}
int fcfg_proto_set_join_req(char *buff, char *env, int64_t version)
{
    FCFGProtoHeader *fcfg_header_pro;
    FCFGProtoJoinReq *fcfg_join_req_pro;

    fcfg_header_pro = (FCFGProtoHeader *)buff;
    fcfg_header_pro->cmd = FCFG_PROTO_JION_REQ;
    int2buff(sizeof(FCFGProtoJoinReq), fcfg_header_pro->body_len);

    fcfg_join_req_pro = (FCFGProtoJoinReq *)(buff + sizeof(FCFGProtoHeader));
    memcpy(fcfg_join_req_pro->env, env, sizeof(fcfg_join_req_pro->env));
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
        fcfg_push_body_pro = (FCFGProtoPushConfigBodyPart *)(((char *)fcfg_push_body_pro) + size +
                name_len +
                value_len);
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

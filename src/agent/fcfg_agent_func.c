
#include <sys/stat.h>
#include "fastcommon/ini_file_reader.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "sf/sf_global.h"
#include "sf/sf_service.h"
#include "sf/sf_util.h"
#include "common/fcfg_types.h"
#include "fcfg_agent_global.h"
#include "fcfg_agent_func.h"

int fcfg_agent_load_config(const char *filename)
{
    IniContext ini_context;
    char agent_config_str[1024];
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

    g_agent_global_vars.join_conn.port = iniGetIntValue(NULL, "server_port",
            &ini_context, 0);
    if (g_agent_global_vars.join_conn.port == 0) {
        lerr("get server_port from file:%s", filename);
        return ENOENT;
    }

    iniFreeContext(&ini_context);

    snprintf(agent_config_str, sizeof(agent_config_str),
            "shm_config_file: %s",
            g_agent_global_vars.shm_config_file);
    sf_log_config_ex(agent_config_str);
    return 0;
}

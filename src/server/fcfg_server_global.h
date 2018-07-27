
#ifndef _FCFG_SERVER_GLOBAL_H
#define _FCFG_SERVER_GLOBAL_H

#include "fastcommon/common_define.h"
#include "fcfg_server_env.h"

typedef struct fcfg_server_reload_all_configs_policy {
    int min_version_changed;
    int min_interval;
    int max_interval;
} FCFGServerReloadAllConfigsPolicy;

typedef struct fcfg_server_global_vars {
    struct {
        char *host;
        int port;
        char *user;
        char *password;
        char *database;
    } db_config;

    FCFGEnvArray *env_array;

    int reload_interval_ms;

    FCFGServerReloadAllConfigsPolicy reload_all_configs_policy;

} FCFGServerGlobalVars;

#ifdef __cplusplus
extern "C" {
#endif

    extern FCFGServerGlobalVars g_server_global_vars;

#ifdef __cplusplus
}
#endif

#endif

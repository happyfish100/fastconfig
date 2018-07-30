#ifndef _FCFG_ADMIN_LIST_CONFIG_H
#define _FCFG_ADMIN_LIST_CONFIG_H

typedef struct fcfg_admin_env_config {
    char *config_file;
    char *config_env;
    char *config_name;
    int limit;
} FCFGAdminListEnvGlobal;

#ifdef __cplusplus
extern "C" {
#endif

extern FCFGAdminListEnvGlobal g_fcfg_admin_list_env;

#define FCFG_ADMIN_LIST_REQUEST_MAX_COUNT   50
#define FCFG_ADMIN_LIST_REQUEST_COUNT       20

#ifdef __cplusplus
}
#endif

#endif

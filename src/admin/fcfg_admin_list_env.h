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

#ifdef __cplusplus
}
#endif

#endif

#ifndef _FCFG_ADMIN_LIST_CONFIG_H
#define _FCFG_ADMIN_LIST_CONFIG_H

typedef struct fcfg_admin_list_config {
    char *config_file;
    char *config_env;
    char *config_name;
    int limit;
} FCFGAdminListConfigGlobal;

#ifdef __cplusplus
extern "C" {
#endif

extern FCFGAdminListConfigGlobal g_fcfg_admin_list_vars;

#define FCFG_ADMIN_LIST_REQUEST_COUNT   20

#ifdef __cplusplus
}
#endif

#endif

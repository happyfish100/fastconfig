#ifndef _FCFG_ADMIN_DEL_CONFIG_H
#define _FCFG_ADMIN_DEL_CONFIG_H

typedef struct fcfg_admin_del_config {
    char *config_file;
    char *config_env;
    char *config_name;
} FCFGAdminDelGlobal;

#ifdef __cplusplus
extern "C" {
#endif
#define FCFG_NETWORK_TIMEOUT_DEFAULT    30
#define FCFG_CONNECT_TIMEOUT_DEFAULT    30

extern FCFGAdminDelGlobal g_fcfg_admin_del_vars;


#ifdef __cplusplus
}
#endif

#endif

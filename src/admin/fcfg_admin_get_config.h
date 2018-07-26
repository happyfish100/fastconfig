#ifndef _FCFG_ADMIN_GET_CONFIG_H
#define _FCFG_ADMIN_GET_CONFIG_H

typedef struct fcfg_admin_get_config {
    char *config_file;
    char *config_env;
    char *config_name;
} FCFGAdminGetGlobal;

#ifdef __cplusplus
extern "C" {
#endif

extern FCFGAdminGetGlobal g_fcfg_admin_get_vars;


#ifdef __cplusplus
}
#endif

#endif

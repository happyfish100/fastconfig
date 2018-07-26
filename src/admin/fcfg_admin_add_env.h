#ifndef _FCFG_ADMIN_ADD_ENV_CONFIG_H
#define _FCFG_ADMIN_ADD_ENV_CONFIG_H

typedef struct fcfg_admin_add_env {
    char *config_file;
    char *config_env;
} FCFGAdminAddEnvGlobal;

#ifdef __cplusplus
extern "C" {
#endif

extern FCFGAdminAddEnvGlobal g_fcfg_admin_add_env;


#ifdef __cplusplus
}
#endif

#endif

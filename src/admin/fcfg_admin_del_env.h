#ifndef _FCFG_ADMIN_DEL_ENV_CONFIG_H
#define _FCFG_ADMIN_DEL_ENV_CONFIG_H

typedef struct fcfg_admin_del_env {
    char *config_file;
    char *config_env;
} FCFGAdminDelEnvGlobal;

#ifdef __cplusplus
extern "C" {
#endif

extern FCFGAdminDelEnvGlobal g_fcfg_admin_del_env;


#ifdef __cplusplus
}
#endif

#endif

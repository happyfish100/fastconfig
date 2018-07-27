#ifndef _FCFG_ADMIN_DEL_ENV_CONFIG_H
#define _FCFG_ADMIN_DEL_ENV_CONFIG_H

typedef struct fcfg_admin_get_env {
    char *config_file;
    char *config_env;
} FCFGAdminGetEnvGlobal;

#ifdef __cplusplus
extern "C" {
#endif

extern FCFGAdminGetEnvGlobal g_fcfg_admin_get_env;


#ifdef __cplusplus
}
#endif

#endif

#ifndef _FCFG_ADMIN_SET_CONFIG_H
#define _FCFG_ADMIN_SET_CONFIG_H

typedef struct fcfg_admin_set_config {
    ConnectionInfo join_conn;
    char *config_filename;
    char *config_env;
    char *config_name;
    char *config_value;
} FCFGAdminSetGlobal;

#ifdef __cplusplus
extern "C" {
#endif

extern FCFGAdminSetGlobal g_fcfg_admin_set_vars;


#ifdef __cplusplus
}
#endif

#endif

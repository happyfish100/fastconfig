#ifndef _FCFG_ADMIN_SET_CONFIG_H
#define _FCFG_ADMIN_SET_CONFIG_H

typedef struct fcfg_admin_set_config {
    ConnectionInfo join_conn;
    int network_timeout;
    int connect_timeout;
    char *config_file;
    char *config_env;
    char *config_name;
    char *config_value;
} FCFGAdminSetGlobal;

#ifdef __cplusplus
extern "C" {
#endif
#define FCFG_NETWORK_TIMEOUT_DEFAULT    30
#define FCFG_CONNECT_TIMEOUT_DEFAULT    30

extern FCFGAdminSetGlobal g_fcfg_admin_set_vars;


#ifdef __cplusplus
}
#endif

#endif

#ifndef _FCFG_ADMIN_FUNC_H
#define _FCFG_ADMIN_FUNC_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fcfg_admin {
    char username[128];
    char secret_key[512];
    ConnectionInfo join_conn;
    int network_timeout;
    int connect_timeout;
} FCFGAdminGlobal;

extern FCFGAdminGlobal g_fcfg_admin_vars;
int fcfg_send_admin_join_request(ConnectionInfo *join_conn, int network_timeout,
        int connect_timeout);
int fcfg_admin_check_response(ConnectionInfo *join_conn,
        FCFGResponseInfo *resp_info, int network_timeout,
        unsigned char resp_cmd);
void fcfg_set_admin_header (FCFGProtoHeader *fcfg_header_proto,
        unsigned char cmd, int body_len);
int fcfg_admin_load_config(const char *filename);

#define FCFG_NETWORK_TIMEOUT_DEFAULT    30
#define FCFG_CONNECT_TIMEOUT_DEFAULT    30

#ifdef __cplusplus
}
#endif

#endif

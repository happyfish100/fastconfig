
#ifndef _FCFG_SERVER_GLOBAL_H
#define _FCFG_SERVER_GLOBAL_H

#include "fastcommon/common_define.h"

typedef struct fcfg_server_global_vars {
    struct {
        char *host;
        int port;
        char *user;
        char *password;
        char *database;
    } db_config;
    char tmp_path[MAX_PATH_SIZE];
} FCFGServerGlobalVars;

#ifdef __cplusplus
extern "C" {
#endif

    extern FCFGServerGlobalVars g_server_global_vars;

#ifdef __cplusplus
}
#endif

#endif


#ifndef _FCFG_SERVER_GLOBAL_H
#define _FCFG_SERVER_GLOBAL_H

#include "fastcommon/common_define.h"

typedef struct fcfg_server_global_vars {
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

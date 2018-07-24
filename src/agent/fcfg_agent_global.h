
#ifndef _FCFG_AGENT_GLOBAL_H
#define _FCFG_AGENT_GLOBAL_H

#include "fastcommon/common_define.h"
#include "shmcache/shmcache.h"
#include "fastcommon/multi_socket_client.h"

typedef struct fcfg_agent_global_vars {
    ConnectionInfo join_conn;
    struct shmcache_context shm_context;
    char tmp_path[MAX_PATH_SIZE];
    char shm_config_file[MAX_PATH_SIZE];
    char env[64];
    char shm_version_key[128];
} FCFGAgentGlobalVars;

#ifdef __cplusplus
extern "C" {
#endif

    extern FCFGAgentGlobalVars g_agent_global_vars;

#ifdef __cplusplus
}
#endif

#endif

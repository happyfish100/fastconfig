
#ifndef _FCFG_AGENT_FUNC_H
#define _FCFG_AGENT_FUNC_H


#ifdef __cplusplus
extern "C" {
#endif

int fcfg_agent_load_config(const char *filename);

#define FCFG_AGENT_SHM_VERSION_KEY_SUFFIX   "shm_version_key"
#ifdef __cplusplus
}
#endif

#endif

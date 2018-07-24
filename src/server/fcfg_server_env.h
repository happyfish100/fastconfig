
#ifndef _FCFG_SERVER_ENV_H
#define _FCFG_SERVER_ENV_H

typedef struct {
    char *env;
} FCFGEnvRecord;

typedef struct {
    FCFGEnvRecord *records;
    int count;
} FCFGEnvArray;

#ifdef __cplusplus
extern "C" {
#endif

    int fcfg_server_env_init();

    void fcfg_server_env_destroy();

    bool fcfg_server_env_exists(const char *env);

#ifdef __cplusplus
}
#endif

#endif

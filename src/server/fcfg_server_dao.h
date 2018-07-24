
#ifndef _FCFG_SERVER_DAO_H
#define _FCFG_SERVER_DAO_H

#include <mysql.h>
#include "fcfg_server_env.h"

typedef struct {
    MYSQL mysql;
    MYSQL_STMT *update_stmt;
    MYSQL_STMT *insert_stmt;
    MYSQL_STMT *delete_stmt;
    MYSQL_STMT *select_stmt;
    MYSQL_STMT *search_stmt;
} FCFGMySQLContext;

typedef struct {
    char *name;
    char *value;
    int64_t version;
    short status;
    int name_len;
    int value_len;
} FCFGConfigRecord;

typedef struct {
    FCFGConfigRecord *records;
    int count;
} FCFGConfigArray;

#ifdef __cplusplus
extern "C" {
#endif

    int fcfg_server_dao_init(FCFGMySQLContext *context);

    void fcfg_server_dao_destroy(FCFGMySQLContext *context);

    int fcfg_server_dao_set(FCFGMySQLContext *context, const char *env,
            const char *name, const char *value);

    int fcfg_server_dao_delete(FCFGMySQLContext *context, const char *env,
            const char *name);

    int fcfg_server_dao_list_by_env_and_version(FCFGMySQLContext *context,
            const char *env, const int64_t version, const int limit,
            FCFGConfigArray *array);

    int fcfg_server_dao_search(FCFGMySQLContext *context,
            const char *env, const char *name, const int limit,
            FCFGConfigArray *array);

    void fcfg_server_dao_free_config_array(FCFGConfigArray *array);

    int fcfg_server_dao_add_env(FCFGMySQLContext *context, const char *env);

    int fcfg_server_dao_del_env(FCFGMySQLContext *context, const char *env);

    int fcfg_server_dao_list_env(FCFGMySQLContext *context, FCFGEnvArray *array);

    void fcfg_server_dao_free_env_array(FCFGEnvArray *array);

#ifdef __cplusplus
}
#endif

#endif


#ifndef _FCFG_SERVER_DAO_H
#define _FCFG_SERVER_DAO_H

#include <mysql.h>


typedef struct {
    MYSQL mysql;
    MYSQL_STMT *update_stmt;
    MYSQL_STMT *insert_stmt;
    MYSQL_STMT *delete_stmt;
    MYSQL_STMT *select_stmt;
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
} FCFGConfigRows;

#ifdef __cplusplus
extern "C" {
#endif

    int fcfg_server_dao_init(FCFGMySQLContext *context);

    void fcfg_server_dao_destroy(FCFGMySQLContext *context);

    int fcfg_server_dao_replace(FCFGMySQLContext *context, const char *env,
            const char *name, const char *value);

    int fcfg_server_dao_delete(FCFGMySQLContext *context, const char *env,
            const char *name);

    int fcfg_server_dao_query_by_env_and_version(FCFGMySQLContext *context,
            const char *env, const int64_t version, const int limit,
            FCFGConfigRows *rows);

    void fcfg_server_dao_free_rows(FCFGConfigRows *rows);

#ifdef __cplusplus
}
#endif

#endif

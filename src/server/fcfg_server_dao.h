
#ifndef _FCFG_SERVER_DAO_H
#define _FCFG_SERVER_DAO_H

#include <mysql.h>


typedef struct {
    MYSQL mysql;
    MYSQL_STMT *update_stmt;
    MYSQL_STMT *insert_stmt;
} MySQLContext;

#ifdef __cplusplus
extern "C" {
#endif

    int fcfg_server_dao_init(MySQLContext *context);

    void fcfg_server_dao_destroy(MySQLContext *context);

    int fcfg_server_dao_replace(MySQLContext *context, const char *env,
            const char *name, const char *value);

#ifdef __cplusplus
}
#endif

#endif

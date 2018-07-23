
#include <sys/stat.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "sf/sf_global.h"
#include "sf/sf_service.h"
#include "common/fcfg_types.h"
#include "fcfg_server_global.h"
#include "fcfg_server_dao.h"

int fcfg_server_dao_init(MySQLContext *context)
{
    bool on;
    int timeout;
    const char *insert_sql = "INSERT INTO fast_config "
        "(env, name, value, version) values (?, ?, ?, ?)";
    const char *update_sql = "update fast_config "
        "set value = ?, version = ? where env = ? and name = ?";

    mysql_init(&context->mysql);
    context->update_stmt = mysql_stmt_init(&context->mysql);
    if (context->update_stmt == NULL) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_init fail", __LINE__);
        return ENOMEM;
    }
    context->insert_stmt = mysql_stmt_init(&context->mysql);
    if (context->insert_stmt == NULL) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_init fail", __LINE__);
        return ENOMEM;
    }

    on = true;
    mysql_options(&context->mysql, MYSQL_OPT_RECONNECT, &on);
    timeout = g_sf_global_vars.connect_timeout;
    mysql_options(&context->mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);

    timeout = g_sf_global_vars.network_timeout;
    mysql_options(&context->mysql, MYSQL_OPT_READ_TIMEOUT, &timeout);

    timeout = g_sf_global_vars.network_timeout;
    mysql_options(&context->mysql, MYSQL_OPT_WRITE_TIMEOUT, &timeout);

    if (mysql_real_connect(&context->mysql,
                g_server_global_vars.db_config.host,
                g_server_global_vars.db_config.user,
                g_server_global_vars.db_config.password,
                g_server_global_vars.db_config.database,
                g_server_global_vars.db_config.port, NULL, 0) == NULL)
    {
        logError("file: "__FILE__", line: %d, "
                "connect to mysql %s:%d fail, error info: %s",
                __LINE__, g_server_global_vars.db_config.host,
                g_server_global_vars.db_config.port,
                mysql_error(&context->mysql));
        return ENOTCONN;
    }

    if (mysql_stmt_prepare(context->update_stmt, update_sql,
                strlen(update_sql)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "prepare stmt fail, error info: %s, sql: %s",
                __LINE__, mysql_stmt_error(context->update_stmt), update_sql);
        return EINVAL;
    }

    if (mysql_stmt_prepare(context->insert_stmt, insert_sql,
                strlen(insert_sql)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "prepare stmt fail, error info: %s, sql: %s",
                __LINE__, mysql_stmt_error(context->insert_stmt), insert_sql);
        return EINVAL;
    }

    return 0;
}

void fcfg_server_dao_destroy(MySQLContext *context)
{
    mysql_stmt_close(context->update_stmt);
    mysql_close(&context->mysql);
}

static int64_t fcfg_server_dao_next_version(MySQLContext *context)
{
    MYSQL_RES *mysql_result;
    MYSQL_ROW row;
    int64_t version;
    const char *update_sql = "update fast_increment "
        "set value=(@nextval:=value+1) where name = 'fast_config_version'";
    const char *nextval_sql = "select @nextval";

    if (mysql_real_query(&context->mysql, update_sql, strlen(update_sql)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_real_query fail, error info: %s, sql: %s",
                __LINE__, mysql_error(&context->mysql), update_sql);
        return -1;
    }

    if (mysql_affected_rows(&context->mysql) != 1) {
        logError("file: "__FILE__", line: %d, "
                "mysql_affected_rows != 1, sql: %s",
                __LINE__, update_sql);
        return -2;
    }

    if (mysql_real_query(&context->mysql, nextval_sql, strlen(nextval_sql)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_real_query fail, error info: %s, sql: %s",
                __LINE__, mysql_error(&context->mysql), nextval_sql);
        return -3;
    }

    mysql_result = mysql_store_result(&context->mysql);
    if (mysql_result == NULL) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_store_result fail, error info: %s, sql: %s",
                __LINE__, mysql_error(&context->mysql), nextval_sql);
        return -4;
    }

    row = mysql_fetch_row(mysql_result);
    if (row == NULL) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_fetch_row fail, error info: %s, sql: %s",
                __LINE__, mysql_error(&context->mysql), nextval_sql);
        return -5;
    }

    version = strtoll(row[0], NULL, 10);
    mysql_free_result(mysql_result);
    return version;
}

int fcfg_server_dao_replace(MySQLContext *context, const char *env,
        const char *name, const char *value)
{
    MYSQL_BIND update_binds[4];
    MYSQL_BIND insert_binds[4];
    int64_t version;
    unsigned long env_len;
    unsigned long name_len;
    unsigned long value_len;

    version = fcfg_server_dao_next_version(context);
    if (version < 0) {
        return EINVAL;
    }

    env_len = strlen(env);
    name_len = strlen(name);
    value_len = strlen(value);

    memset(update_binds, 0, sizeof(update_binds));

    update_binds[0].buffer_type = MYSQL_TYPE_STRING;
    update_binds[0].buffer = (char *)value;
    update_binds[0].length = &value_len;

    update_binds[1].buffer_type = MYSQL_TYPE_LONGLONG;
    update_binds[1].buffer = (char *)&version;

    update_binds[2].buffer_type = MYSQL_TYPE_STRING;
    update_binds[2].buffer = (char *)env;
    update_binds[2].length = &env_len;

    update_binds[3].buffer_type = MYSQL_TYPE_STRING;
    update_binds[3].buffer = (char *)name;
    update_binds[3].length = &name_len;

    if (mysql_stmt_bind_param(context->update_stmt, update_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_param fail, error info: %s",
                __LINE__, mysql_stmt_error(context->update_stmt));
        return EINVAL;
    }

    if (mysql_stmt_execute(context->update_stmt) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_execute fail, error info: %s",
                __LINE__, mysql_stmt_error(context->update_stmt));
        return EINVAL;
    }
    if (mysql_stmt_affected_rows(context->update_stmt) != 0) {
        return 0;
    }

    memset(insert_binds, 0, sizeof(insert_binds));
    insert_binds[0].buffer_type = MYSQL_TYPE_STRING;
    insert_binds[0].buffer = (char *)env;
    insert_binds[0].length = &env_len;

    insert_binds[1].buffer_type = MYSQL_TYPE_STRING;
    insert_binds[1].buffer = (char *)name;
    insert_binds[1].length = &name_len;

    insert_binds[2].buffer_type = MYSQL_TYPE_STRING;
    insert_binds[2].buffer = (char *)value;
    insert_binds[2].length = &value_len;

    insert_binds[3].buffer_type = MYSQL_TYPE_LONGLONG;
    insert_binds[3].buffer = (char *)&version;

    if (mysql_stmt_bind_param(context->insert_stmt, insert_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_param fail, error info: %s",
                __LINE__, mysql_stmt_error(context->insert_stmt));
        return EINVAL;
    }

    if (mysql_stmt_execute(context->insert_stmt) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_execute fail, error info: %s",
                __LINE__, mysql_stmt_error(context->insert_stmt));
        return EINVAL;
    }
    return 0;
}


#include <sys/stat.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "sf/sf_global.h"
#include "sf/sf_service.h"
#include "common/fcfg_types.h"
#include "fcfg_server_global.h"
#include "fcfg_server_dao.h"

#define FCFG_MYSQL_STMT_INIT(stmt, mysql) \
    do {  \
        stmt = mysql_stmt_init(mysql); \
        if (stmt == NULL) {   \
            logError("file: "__FILE__", line: %d, "  \
                    "call mysql_stmt_init fail", __LINE__); \
            return ENOMEM; \
        } \
    } while (0)

#define FCFG_MYSQL_STMT_PREPARE(stmt, sql) \
    do {  \
        if (mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) { \
            logError("file: "__FILE__", line: %d, "  \
                    "prepare stmt fail, error info: %s, sql: %s", \
                    __LINE__, mysql_stmt_error(stmt), sql);  \
            return EINVAL;  \
        } \
    } while (0)

int fcfg_server_dao_init(FCFGMySQLContext *context)
{
    bool on;
    int timeout;
    const char *insert_sql = "INSERT INTO fast_config "
        "(env, name, value, version, status) VALUES (?, ?, ?, ?, 0)";
    const char *update_sql = "UPDATE fast_config "
        "SET value = ?, version = ?, status = 0 WHERE env = ? AND name = ?";
    const char *delete_sql = "UPDATE fast_config "
        "SET version = ?, status = 1 WHERE env = ? AND name = ? and status = 0";
    const char *select_sql = "SELECT name, value, version, status FROM fast_config "
        "WHERE env = ? AND version > ? ORDER BY version limit ?";
    const char *search_sql = "SELECT name, value, version, status FROM fast_config "
        "WHERE env = ? AND name like ? and status = 0 ORDER BY version limit ?";

    mysql_init(&context->mysql);
    FCFG_MYSQL_STMT_INIT(context->update_stmt, &context->mysql);
    FCFG_MYSQL_STMT_INIT(context->insert_stmt, &context->mysql);
    FCFG_MYSQL_STMT_INIT(context->delete_stmt, &context->mysql);
    FCFG_MYSQL_STMT_INIT(context->select_stmt, &context->mysql);
    FCFG_MYSQL_STMT_INIT(context->search_stmt, &context->mysql);

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

    FCFG_MYSQL_STMT_PREPARE(context->update_stmt, update_sql);
    FCFG_MYSQL_STMT_PREPARE(context->insert_stmt, insert_sql);
    FCFG_MYSQL_STMT_PREPARE(context->delete_stmt, delete_sql);
    FCFG_MYSQL_STMT_PREPARE(context->select_stmt, select_sql);
    FCFG_MYSQL_STMT_PREPARE(context->search_stmt, search_sql);

    return 0;
}

void fcfg_server_dao_destroy(FCFGMySQLContext *context)
{
    mysql_stmt_close(context->update_stmt);
    mysql_stmt_close(context->insert_stmt);
    mysql_stmt_close(context->delete_stmt);
    mysql_stmt_close(context->select_stmt);
    mysql_stmt_close(context->search_stmt);
    mysql_close(&context->mysql);
}

static int64_t fcfg_server_dao_next_version(FCFGMySQLContext *context)
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

int fcfg_server_dao_set(FCFGMySQLContext *context, const char *env,
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

int fcfg_server_dao_delete(FCFGMySQLContext *context, const char *env,
        const char *name)
{
    MYSQL_BIND delete_binds[3];
    int64_t version;
    unsigned long env_len;
    unsigned long name_len;

    version = fcfg_server_dao_next_version(context);
    if (version < 0) {
        return EINVAL;
    }

    env_len = strlen(env);
    name_len = strlen(name);
    memset(delete_binds, 0, sizeof(delete_binds));

    delete_binds[0].buffer_type = MYSQL_TYPE_LONGLONG;
    delete_binds[0].buffer = (char *)&version;

    delete_binds[1].buffer_type = MYSQL_TYPE_STRING;
    delete_binds[1].buffer = (char *)env;
    delete_binds[1].length = &env_len;

    delete_binds[2].buffer_type = MYSQL_TYPE_STRING;
    delete_binds[2].buffer = (char *)name;
    delete_binds[2].length = &name_len;

    if (mysql_stmt_bind_param(context->delete_stmt, delete_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_param fail, error info: %s",
                __LINE__, mysql_stmt_error(context->delete_stmt));
        return EINVAL;
    }

    if (mysql_stmt_execute(context->delete_stmt) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_execute fail, error info: %s",
                __LINE__, mysql_stmt_error(context->delete_stmt));
        return EINVAL;
    }
    if (mysql_stmt_affected_rows(context->delete_stmt) == 0) {
        return ENOENT;
    }
    return 0;
}

static int fcfg_server_dao_store_rows(MYSQL_STMT *stmt, FCFGConfigArray *array)
{
    MYSQL_BIND result_binds[4];
    int row_count;
    int bytes;
    struct {
        char name[FCFG_CONFIG_NAME_SIZE];
        char value[FCFG_CONFIG_VALUE_SIZE];
        int64_t version;
        short status;
        unsigned long name_len;
        unsigned long value_len;
    } buffer;
    bool is_null[4];
    bool error[4];
    FCFGConfigRecord *current;
    FCFGConfigRecord *end;

    memset(result_binds, 0, sizeof(result_binds));
    result_binds[0].buffer_type = MYSQL_TYPE_STRING;
    result_binds[0].buffer = buffer.name;
    result_binds[0].buffer_length = FCFG_CONFIG_NAME_SIZE;
    result_binds[0].is_null = &is_null[0];
    result_binds[0].length = &buffer.name_len;
    result_binds[0].error = &error[0];

    result_binds[1].buffer_type = MYSQL_TYPE_STRING;
    result_binds[1].buffer = buffer.value;
    result_binds[1].buffer_length = FCFG_CONFIG_VALUE_SIZE;
    result_binds[1].is_null = &is_null[1];
    result_binds[1].length = &buffer.value_len;
    result_binds[1].error = &error[1];

    result_binds[2].buffer_type = MYSQL_TYPE_LONGLONG;
    result_binds[2].buffer = (char *)&buffer.version;
    result_binds[2].is_null = &is_null[2];
    result_binds[2].error = &error[2];

    result_binds[3].buffer_type = MYSQL_TYPE_SHORT;
    result_binds[3].buffer = (char *)&buffer.status;
    result_binds[3].is_null = &is_null[3];
    result_binds[3].error = &error[3];

    if (mysql_stmt_bind_result(stmt, result_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_result fail, error info: %s",
                __LINE__, mysql_stmt_error(stmt));
        array->records = NULL;
        array->count = 0;
        return EINVAL;
    }

    if (mysql_stmt_execute(stmt) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_execute fail, error info: %s",
                __LINE__, mysql_stmt_error(stmt));
        array->records = NULL;
        array->count = 0;
        return EINVAL;
    }

    if (mysql_stmt_store_result(stmt) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_store_result fail, error info: %s",
                __LINE__, mysql_stmt_error(stmt));
        array->records = NULL;
        array->count = 0;
        return EINVAL;
    }

    row_count = mysql_stmt_num_rows(stmt);
    if (row_count == 0) {
        array->count = 0;
        array->records = NULL;
        return 0;
    }

    bytes = sizeof(FCFGConfigRecord) * row_count;
    array->records = (FCFGConfigRecord *)malloc(bytes);
    if (array->records == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, bytes);
        array->count = 0;
        return ENOMEM;
    }

    end = array->records + row_count;
    for (current=array->records; current<end; current++) {
        if (mysql_stmt_fetch(stmt) != 0) {
            logError("file: "__FILE__", line: %d, "
                    "call mysql_stmt_fetch fail, error info: %s",
                    __LINE__, mysql_stmt_error(stmt));
            array->count = current - array->records;
            fcfg_server_dao_free_config_array(array);
            return EFAULT;
        }

        bytes = buffer.name_len + buffer.value_len + 1;
        current->name = (char *)malloc(bytes);
        if (current->name == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "malloc %d bytes fail", __LINE__, bytes);
            array->count = current - array->records;
            fcfg_server_dao_free_config_array(array);
            return ENOMEM;
        }
        current->value = current->name + buffer.name_len;
        memcpy(current->name, buffer.name, buffer.name_len);
        memcpy(current->value, buffer.value, buffer.value_len);
        current->version = buffer.version;
        current->status = buffer.status;
        current->name_len = buffer.name_len;
        current->value_len = buffer.value_len;

        logInfo("name: %.*s, value: %.*s, version: %"PRId64", status: %d",
                current->name_len, current->name,
                current->value_len, current->value,
                current->version, current->status);
    }

    array->count = row_count;
    return 0;
}

int fcfg_server_dao_list_by_env_and_version(FCFGMySQLContext *context,
        const char *env, const int64_t version, const int limit,
        FCFGConfigArray *array)
{
    MYSQL_BIND select_binds[3];
    unsigned long env_len;

    env_len = strlen(env);
    memset(select_binds, 0, sizeof(select_binds));

    select_binds[0].buffer_type = MYSQL_TYPE_STRING;
    select_binds[0].buffer = (char *)env;
    select_binds[0].length = &env_len;

    select_binds[1].buffer_type = MYSQL_TYPE_LONGLONG;
    select_binds[1].buffer = (char *)&version;

    select_binds[2].buffer_type = MYSQL_TYPE_LONG;
    select_binds[2].buffer = (char *)&limit;

    if (mysql_stmt_bind_param(context->select_stmt, select_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_param fail, error info: %s",
                __LINE__, mysql_stmt_error(context->select_stmt));
        array->records = NULL;
        array->count = 0;
        return EINVAL;
    }

    return fcfg_server_dao_store_rows(context->select_stmt, array);
}

int fcfg_server_dao_search(FCFGMySQLContext *context,
        const char *env, const char *name, const int limit,
        FCFGConfigArray *array)
{
    MYSQL_BIND search_binds[3];
    unsigned long env_len;
    unsigned long name_len;

    env_len = strlen(env);
    name_len = strlen(name);
    memset(search_binds, 0, sizeof(search_binds));

    search_binds[0].buffer_type = MYSQL_TYPE_STRING;
    search_binds[0].buffer = (char *)env;
    search_binds[0].length = &env_len;

    search_binds[1].buffer_type = MYSQL_TYPE_STRING;
    search_binds[1].buffer = (char *)name;
    search_binds[1].length = &name_len;

    search_binds[2].buffer_type = MYSQL_TYPE_LONG;
    search_binds[2].buffer = (char *)&limit;

    if (mysql_stmt_bind_param(context->search_stmt, search_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_param fail, error info: %s",
                __LINE__, mysql_stmt_error(context->search_stmt));
        array->records = NULL;
        array->count = 0;
        return EINVAL;
    }

    return fcfg_server_dao_store_rows(context->search_stmt, array);
}

void fcfg_server_dao_free_config_array(FCFGConfigArray *array)
{
    FCFGConfigRecord *current;
    FCFGConfigRecord *end;

    if (array->records == NULL) {
        return;
    }

    end = array->records + array->count;
    for (current=array->records; current<end; current++) {
        if (current->name != NULL) {
            free(current->name);
        }
    }

    free(array->records);
    array->records = NULL;
    array->count = 0;
}

static int fcfg_server_dao_env_execute(FCFGMySQLContext *context,
        const char *sql, const char *env)
{
    MYSQL_STMT *stmt;
    MYSQL_BIND binds[1];
    unsigned long env_len;
    int result;

    FCFG_MYSQL_STMT_INIT(stmt, &context->mysql);
    FCFG_MYSQL_STMT_PREPARE(stmt, sql);

    env_len = strlen(env);
    memset(binds, 0, sizeof(binds));
    binds[0].buffer_type = MYSQL_TYPE_STRING;
    binds[0].buffer = (char *)env;
    binds[0].length = &env_len;

    do {
        if (mysql_stmt_bind_param(stmt, binds) != 0) {
            logError("file: "__FILE__", line: %d, "
                    "call mysql_stmt_bind_param fail, "
                    "error info: %s, stmt: %s",
                    __LINE__, mysql_stmt_error(stmt), sql);
            result = EINVAL;
            break;
        }

        if (mysql_stmt_execute(stmt) != 0) {
            logError("file: "__FILE__", line: %d, "
                    "call mysql_stmt_execute fail, "
                    "error info: %s, stmt: %s",
                    __LINE__, mysql_stmt_error(stmt), sql);
            result = EINVAL;
            break;
        }

        result = 0;
    } while (0);

    mysql_stmt_close(stmt);
    return result;
}

int fcfg_server_dao_add_env(FCFGMySQLContext *context, const char *env)
{
    const char *insert_sql = "INSERT INTO fast_environment "
        "(env) VALUES (?)";
    return fcfg_server_dao_env_execute(context, insert_sql, env);
}

int fcfg_server_dao_del_env(FCFGMySQLContext *context, const char *env)
{
    const char *delete_sql = "DELETE FROM fast_environment WHERE env = ?";
    return fcfg_server_dao_env_execute(context, delete_sql, env);
}

int fcfg_server_dao_list_env(FCFGMySQLContext *context, const char *env,
        FCFGEnvArray *array)
{
    MYSQL_RES *mysql_result;
    MYSQL_ROW row;
    FCFGEnvRecord *current;
    FCFGEnvRecord  *end;
    int row_count;
    int bytes;
    const char *select_sql = "SELECT env FROM fast_environment ORDER BY env";

    if (mysql_real_query(&context->mysql, select_sql, strlen(select_sql)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_real_query fail, error info: %s, sql: %s",
                __LINE__, mysql_error(&context->mysql), select_sql);
        return EINVAL;
    }

    mysql_result = mysql_store_result(&context->mysql);
    if (mysql_result == NULL) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_store_result fail, error info: %s, sql: %s",
                __LINE__, mysql_error(&context->mysql), select_sql);
        return EINVAL;
    }

    row_count = mysql_num_rows(mysql_result);
    if (row_count == 0) {
        array->count = 0;
        array->records = NULL;
        mysql_free_result(mysql_result);
        return 0;
    }

    bytes = sizeof(FCFGEnvRecord) * row_count;
    array->records = (FCFGEnvRecord *)malloc(bytes);
    if (array->records == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, bytes);
        array->count = 0;
        mysql_free_result(mysql_result);
        return ENOMEM;
    }

    array->count = row_count;
    end = array->records + row_count;
    for (current=array->records; current<end; current++) {
        if ((row=mysql_fetch_row(mysql_result)) == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "call mysql_fetch_row fail, error info: %s",
                    __LINE__, mysql_error(&context->mysql));
            array->count = current - array->records;
            break;
        }

        current->env = strdup(row[0]);
        if (current->env == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "strdup %s fail", __LINE__, row[0]);
            array->count = current - array->records;
            break;
        }
    }
    mysql_free_result(mysql_result);

    if (current < end) {
        fcfg_server_dao_free_env_rows(array);
        return EFAULT;
    }

    return 0;
}

void fcfg_server_dao_free_env_rows(FCFGEnvArray *array)
{
    FCFGEnvRecord *current;
    FCFGEnvRecord  *end;
    
    if (array->records == NULL) {
        return;
    }

    end = array->records + array->count;
    for (current=array->records; current<end; current++) {
        if (current->env != NULL) {
            free(current->env);
        }
    }

    free(array->records);
    array->records = NULL;
    array->count = 0;
}

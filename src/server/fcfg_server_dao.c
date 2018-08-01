
#include <sys/stat.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "sf/sf_global.h"
#include "sf/sf_service.h"
#include "common/fcfg_types.h"
#include "fcfg_server_global.h"
#include "fcfg_server_dao.h"

#define FCFG_KEY_NAME_ENVIRONMENT_VERSION  "fast_environment_version"
#define FCFG_KEY_NAME_CONFIG_VERSION       "fast_config_version"

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
#define CONFIG_SELECT_SQL "SELECT name, value, version, status, " \
        "UNIX_TIMESTAMP(create_time), UNIX_TIMESTAMP(update_time) FROM fast_config "

    my_bool on;
    int timeout;
    const char *insert_sql = "INSERT INTO fast_config "
        "(env, name, value, version, status) VALUES (?, ?, ?, ?, 0)";
    const char *update_sql = "UPDATE fast_config "
        "SET value = ?, version = ?, status = 0 WHERE env = ? AND name = ?";
    const char *delete_sql = "UPDATE fast_config "
        "SET version = ?, status = 1 WHERE env = ? AND name = ? and status = 0";
    const char *select_sql = CONFIG_SELECT_SQL
        "WHERE env = ? AND version > ? ORDER BY version limit ?";
    const char *search_sql = CONFIG_SELECT_SQL
        "WHERE env = ? AND name like ? and status = 0 ORDER BY name limit ?, ?";
    const char *get_pk_sql = CONFIG_SELECT_SQL
        "WHERE env = ? AND name = ? and status = 0";
    const char *max_env_ver_sql = "SELECT MAX(version) FROM fast_environment";
    const char *max_cfg_ver_sql = "SELECT MAX(version) FROM fast_config "
        "WHERE env = ?";

    mysql_init(&context->mysql);
    FCFG_MYSQL_STMT_INIT(context->admin.update_stmt, &context->mysql);
    FCFG_MYSQL_STMT_INIT(context->admin.insert_stmt, &context->mysql);
    FCFG_MYSQL_STMT_INIT(context->admin.delete_stmt, &context->mysql);
    FCFG_MYSQL_STMT_INIT(context->agent.select_stmt, &context->mysql);
    FCFG_MYSQL_STMT_INIT(context->admin.search_stmt, &context->mysql);
    FCFG_MYSQL_STMT_INIT(context->admin.get_pk_stmt, &context->mysql);
    FCFG_MYSQL_STMT_INIT(context->monitor.max_env_ver_stmt, &context->mysql);
    FCFG_MYSQL_STMT_INIT(context->monitor.max_cfg_ver_stmt, &context->mysql);

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

    FCFG_MYSQL_STMT_PREPARE(context->admin.update_stmt, update_sql);
    FCFG_MYSQL_STMT_PREPARE(context->admin.insert_stmt, insert_sql);
    FCFG_MYSQL_STMT_PREPARE(context->admin.delete_stmt, delete_sql);
    FCFG_MYSQL_STMT_PREPARE(context->agent.select_stmt, select_sql);
    FCFG_MYSQL_STMT_PREPARE(context->admin.search_stmt, search_sql);
    FCFG_MYSQL_STMT_PREPARE(context->admin.get_pk_stmt, get_pk_sql);
    FCFG_MYSQL_STMT_PREPARE(context->monitor.max_env_ver_stmt, max_env_ver_sql);
    FCFG_MYSQL_STMT_PREPARE(context->monitor.max_cfg_ver_stmt, max_cfg_ver_sql);

    return 0;
}

void fcfg_server_dao_destroy(FCFGMySQLContext *context)
{
    mysql_stmt_close(context->admin.update_stmt);
    mysql_stmt_close(context->admin.insert_stmt);
    mysql_stmt_close(context->admin.delete_stmt);
    mysql_stmt_close(context->agent.select_stmt);
    mysql_stmt_close(context->admin.search_stmt);
    mysql_close(&context->mysql);
}

static int64_t fcfg_server_dao_next_version(FCFGMySQLContext *context,
        const char *name)
{
    MYSQL_RES *mysql_result;
    MYSQL_ROW row;
    int64_t version;
    int len;
    char update_sql[256];
    const char *nextval_sql = "SELECT @nextval";
   
    len = sprintf(update_sql, "UPDATE fast_increment "
        "SET value=(@nextval:=value+1) WHERE name = '%s'", name);
    if (mysql_real_query(&context->mysql, update_sql, len) != 0) {
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

#define fcfg_server_dao_next_config_version(context) \
    fcfg_server_dao_next_version(context, FCFG_KEY_NAME_CONFIG_VERSION)

#define fcfg_server_dao_next_env_version(context) \
    fcfg_server_dao_next_version(context, FCFG_KEY_NAME_ENVIRONMENT_VERSION)

int fcfg_server_dao_set_config(FCFGMySQLContext *context, const char *env,
        const char *name, const char *value)
{
    MYSQL_BIND update_binds[4];
    MYSQL_BIND insert_binds[4];
    int64_t version;
    unsigned long env_len;
    unsigned long name_len;
    unsigned long value_len;
    FCFGConfigArray array;

    if (fcfg_server_dao_get_config(context, env, name, &array) == 0
            && array.count == 1)
    {
        bool same;
        same = (strcmp(value, array.rows[0].value.str) == 0);
        fcfg_server_dao_free_config_array(&array);
        if (same) {
            return 0;
        }
    }

    version = fcfg_server_dao_next_config_version(context);
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

    if (mysql_stmt_bind_param(context->admin.update_stmt, update_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_param fail, error info: %s",
                __LINE__, mysql_stmt_error(context->admin.update_stmt));
        return EINVAL;
    }

    if (mysql_stmt_execute(context->admin.update_stmt) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_execute fail, error info: %s",
                __LINE__, mysql_stmt_error(context->admin.update_stmt));
        return EINVAL;
    }
    if (mysql_stmt_affected_rows(context->admin.update_stmt) != 0) {
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

    if (mysql_stmt_bind_param(context->admin.insert_stmt, insert_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_param fail, error info: %s",
                __LINE__, mysql_stmt_error(context->admin.insert_stmt));
        return EINVAL;
    }

    if (mysql_stmt_execute(context->admin.insert_stmt) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_execute fail, error info: %s",
                __LINE__, mysql_stmt_error(context->admin.insert_stmt));
        return EINVAL;
    }

    return 0;
}

int fcfg_server_dao_del_config(FCFGMySQLContext *context, const char *env,
        const char *name)
{
    MYSQL_BIND delete_binds[3];
    int64_t version;
    unsigned long env_len;
    unsigned long name_len;

    version = fcfg_server_dao_next_config_version(context);
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

    if (mysql_stmt_bind_param(context->admin.delete_stmt, delete_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_param fail, error info: %s",
                __LINE__, mysql_stmt_error(context->admin.delete_stmt));
        return EINVAL;
    }

    if (mysql_stmt_execute(context->admin.delete_stmt) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_execute fail, error info: %s",
                __LINE__, mysql_stmt_error(context->admin.delete_stmt));
        return EINVAL;
    }
    if (mysql_stmt_affected_rows(context->admin.delete_stmt) == 0) {
        return ENOENT;
    }
    return 0;
}

static int fcfg_server_dao_store_rows(MYSQL_STMT *stmt, FCFGConfigArray *array)
{
    MYSQL_BIND result_binds[6];
    int row_count;
    int bytes;
    struct {
        char name[FCFG_CONFIG_NAME_SIZE];
        char value[FCFG_CONFIG_VALUE_SIZE];
        int64_t version;
        short status;
        unsigned long name_len;
        unsigned long value_len;
        int create_time;
        int update_time;
    } buffer;
    my_bool is_null[6];
    my_bool error[6];
    FCFGConfigEntry *current;
    FCFGConfigEntry *end;

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

    result_binds[4].buffer_type = MYSQL_TYPE_LONG;
    result_binds[4].buffer = (char *)&buffer.create_time;
    result_binds[4].is_null = &is_null[4];
    result_binds[4].error = &error[4];

    result_binds[5].buffer_type = MYSQL_TYPE_LONG;
    result_binds[5].buffer = (char *)&buffer.update_time;
    result_binds[5].is_null = &is_null[5];
    result_binds[5].error = &error[5];

    if (mysql_stmt_bind_result(stmt, result_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_result fail, error info: %s",
                __LINE__, mysql_stmt_error(stmt));
        array->rows = NULL;
        array->alloc = array->count = 0;
        return EINVAL;
    }

    if (mysql_stmt_execute(stmt) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_execute fail, error info: %s",
                __LINE__, mysql_stmt_error(stmt));
        array->rows = NULL;
        array->alloc = array->count = 0;
        return EINVAL;
    }

    if (mysql_stmt_store_result(stmt) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_store_result fail, error info: %s",
                __LINE__, mysql_stmt_error(stmt));
        array->rows = NULL;
        array->alloc = array->count = 0;
        return EINVAL;
    }

    row_count = mysql_stmt_num_rows(stmt);
    if (row_count == 0) {
        array->alloc = array->count = 0;
        array->rows = NULL;
        return 0;
    }

    if (row_count <= 2) {  //fast path
        array->alloc = row_count;
    } else {
        array->alloc = 4;
        while (array->alloc < row_count) {
            array->alloc *= 2;
        }
    }

    bytes = sizeof(FCFGConfigEntry) * array->alloc;
    array->rows = (FCFGConfigEntry *)malloc(bytes);
    if (array->rows == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, bytes);
        array->alloc = array->count = 0;
        return ENOMEM;
    }

    end = array->rows + row_count;
    for (current=array->rows; current<end; current++) {
        if (mysql_stmt_fetch(stmt) != 0) {
            logError("file: "__FILE__", line: %d, "
                    "call mysql_stmt_fetch fail, error info: %s",
                    __LINE__, mysql_stmt_error(stmt));
            array->count = current - array->rows;
            fcfg_server_dao_free_config_array(array);
            return EFAULT;
        }

        bytes = buffer.name_len + buffer.value_len + 2;
        current->name.str = (char *)malloc(bytes);
        if (current->name.str == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "malloc %d bytes fail", __LINE__, bytes);
            array->count = current - array->rows;
            fcfg_server_dao_free_config_array(array);
            return ENOMEM;
        }
        current->value.str = current->name.str + buffer.name_len + 1;
        memcpy(current->name.str, buffer.name, buffer.name_len + 1);
        memcpy(current->value.str, buffer.value, buffer.value_len + 1);
        current->version = buffer.version;
        current->status = buffer.status;
        current->create_time = buffer.create_time;
        current->update_time = buffer.update_time;
        current->name.len = buffer.name_len;
        current->value.len = buffer.value_len;

        logInfo("name: %.*s, value: %.*s, version: %"PRId64", status: %d, "
                "create_time: %ld, update_time: %ld",
                current->name.len, current->name.str,
                current->value.len, current->value.str,
                current->version, current->status,
                (long)current->create_time, (long)current->update_time);
    }

    array->count = row_count;
    return 0;
}

int fcfg_server_dao_list_config_by_env_and_version(FCFGMySQLContext *context,
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

    if (mysql_stmt_bind_param(context->agent.select_stmt, select_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_param fail, error info: %s",
                __LINE__, mysql_stmt_error(context->agent.select_stmt));
        array->rows = NULL;
        array->count = 0;
        return EINVAL;
    }

    return fcfg_server_dao_store_rows(context->agent.select_stmt, array);
}

int fcfg_server_dao_search_config(FCFGMySQLContext *context,
        const char *env, const char *name, const int offset,
        const int limit, FCFGConfigArray *array)
{
    MYSQL_BIND search_binds[4];
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
    search_binds[2].buffer = (char *)&offset;

    search_binds[3].buffer_type = MYSQL_TYPE_LONG;
    search_binds[3].buffer = (char *)&limit;

    if (mysql_stmt_bind_param(context->admin.search_stmt, search_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_param fail, error info: %s",
                __LINE__, mysql_stmt_error(context->admin.search_stmt));
        array->rows = NULL;
        array->count = 0;
        return EINVAL;
    }

    return fcfg_server_dao_store_rows(context->admin.search_stmt, array);
}

int fcfg_server_dao_get_config(FCFGMySQLContext *context, const char *env,
        const char *name, FCFGConfigArray *array)
{
    MYSQL_BIND get_pk_binds[2];
    unsigned long env_len;
    unsigned long name_len;

    env_len = strlen(env);
    name_len = strlen(name);
    memset(get_pk_binds, 0, sizeof(get_pk_binds));

    get_pk_binds[0].buffer_type = MYSQL_TYPE_STRING;
    get_pk_binds[0].buffer = (char *)env;
    get_pk_binds[0].length = &env_len;

    get_pk_binds[1].buffer_type = MYSQL_TYPE_STRING;
    get_pk_binds[1].buffer = (char *)name;
    get_pk_binds[1].length = &name_len;

    if (mysql_stmt_bind_param(context->admin.get_pk_stmt, get_pk_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_param fail, error info: %s",
                __LINE__, mysql_stmt_error(context->admin.get_pk_stmt));
        array->rows = NULL;
        array->count = 0;
        return EINVAL;
    }

    return fcfg_server_dao_store_rows(context->admin.get_pk_stmt, array);
}

int fcfg_server_dao_copy_config_array(FCFGConfigArray *src, FCFGConfigArray *dest)
{
    FCFGConfigEntry *cur;
    FCFGConfigEntry *end;
    FCFGConfigEntry *out;
    int bytes;

    if (src->count == 0) {
        return 0;
    }

    out = dest->rows + dest->count;
    end = src->rows + src->count;
    for (cur=src->rows; cur<end; cur++, out++) {
        out->name.len = cur->name.len;
        out->value.len = cur->value.len;
        out->version = cur->version;
        out->status = cur->status;
        out->create_time = cur->create_time;
        out->update_time = cur->update_time;

        bytes = cur->name.len + cur->value.len + 2;
        out->name.str = (char *)malloc(bytes);
        if (out->name.str == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "malloc %d bytes fail", __LINE__, bytes);
            return ENOMEM;
        }
        out->value.str = out->name.str + cur->name.len + 1;
        memcpy(out->name.str, cur->name.str, bytes);
    }

    dest->count += src->count;
    return 0;
}

void fcfg_server_dao_free_config_array(FCFGConfigArray *array)
{
    FCFGConfigEntry *current;
    FCFGConfigEntry *end;

    if (array->rows == NULL) {
        return;
    }

    end = array->rows + array->count;
    for (current=array->rows; current<end; current++) {
        if (current->name.str != NULL) {
            free(current->name.str);
        }
    }

    free(array->rows);
    array->rows = NULL;
    array->alloc = array->count = 0;
}

static int fcfg_server_dao_env_execute(FCFGMySQLContext *context,
        const char *sql, const char *env, int *affected_rows)
{
    MYSQL_STMT *stmt;
    MYSQL_BIND binds[2];
    unsigned long env_len;
    int64_t version;
    int result;

    version = fcfg_server_dao_next_env_version(context);
    if (version < 0) {
        return EINVAL;
    }

    FCFG_MYSQL_STMT_INIT(stmt, &context->mysql);
    FCFG_MYSQL_STMT_PREPARE(stmt, sql);

    env_len = strlen(env);
    memset(binds, 0, sizeof(binds));

    binds[0].buffer_type = MYSQL_TYPE_LONGLONG;
    binds[0].buffer = (char *)&version;

    binds[1].buffer_type = MYSQL_TYPE_STRING;
    binds[1].buffer = (char *)env;
    binds[1].length = &env_len;

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

        if (affected_rows != NULL) {
            *affected_rows = mysql_stmt_affected_rows(stmt);
        }

        result = 0;
    } while (0);

    mysql_stmt_close(stmt);
    return result;
}

int fcfg_server_dao_add_env(FCFGMySQLContext *context, const char *env)
{
    int affected_rows;
    int result;
    const char *update_sql = "UPDATE fast_environment SET status = 0, "
        "version = ? WHERE env = ?";
    const char *insert_sql = "INSERT INTO fast_environment "
        "(version, env, status) VALUES (?, ?, 0)";

    affected_rows = 0;
    if ((result=fcfg_server_dao_env_execute(context, update_sql, env,
                    &affected_rows)) != 0)
    {
        return result;
    }
    if (affected_rows == 0) {
        return fcfg_server_dao_env_execute(context, insert_sql, env, &affected_rows);
    } else {
        return 0;
    }
}

int fcfg_server_dao_del_env(FCFGMySQLContext *context, const char *env)
{
    const char *delete_sql = "UPDATE fast_environment SET status = 1, "
        "version = ? WHERE env = ?";
    return fcfg_server_dao_env_execute(context, delete_sql, env, NULL);
}

static int fcfg_server_dao_do_list_env(FCFGMySQLContext *context, const char *env,
        FCFGEnvArray *array)
{
    MYSQL_RES *mysql_result;
    MYSQL_ROW row;
    FCFGEnvEntry *current;
    FCFGEnvEntry  *end;
    int row_count;
    int bytes;
    int sql_len;
    char select_sql[512];
    
    strcpy(select_sql, "SELECT env, UNIX_TIMESTAMP(create_time), "
        "UNIX_TIMESTAMP(update_time) FROM fast_environment "
        "WHERE status = 0");
    sql_len = strlen(select_sql);
    if (env != NULL) {
        char escaped_env[2 * FCFG_CONFIG_ENV_SIZE];
        mysql_real_escape_string_quote(&context->mysql, escaped_env,
                env, strlen(env), '\'');
        sql_len += sprintf(select_sql + sql_len, " AND env = '%s'",
                escaped_env);
    } else {
        sql_len += sprintf(select_sql + sql_len, " ORDER BY env");
    }

    logInfo("do_list_env SQL: %s", select_sql);

    if (mysql_real_query(&context->mysql, select_sql, sql_len) != 0) {
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
        array->rows = NULL;
        mysql_free_result(mysql_result);
        return 0;
    }

    bytes = sizeof(FCFGEnvEntry) * row_count;
    array->rows = (FCFGEnvEntry *)malloc(bytes);
    if (array->rows == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, bytes);
        array->count = 0;
        mysql_free_result(mysql_result);
        return ENOMEM;
    }

    array->count = row_count;
    end = array->rows + row_count;
    for (current=array->rows; current<end; current++) {
        if ((row=mysql_fetch_row(mysql_result)) == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "call mysql_fetch_row fail, error info: %s",
                    __LINE__, mysql_error(&context->mysql));
            array->count = current - array->rows;
            break;
        }

        current->env.str = strdup(row[0]);
        if (current->env.str == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "strdup %s fail", __LINE__, row[0]);
            array->count = current - array->rows;
            break;
        }
        current->create_time = strtoll(row[1], NULL, 10);
        current->update_time = strtoll(row[2], NULL, 10);
    }
    mysql_free_result(mysql_result);

    if (current < end) {
        fcfg_server_dao_free_env_array(array);
        return EFAULT;
    }

    return 0;
}

int fcfg_server_dao_list_env(FCFGMySQLContext *context, FCFGEnvArray *array)
{
    const char *env = NULL;
    return fcfg_server_dao_do_list_env(context, env, array);
}

int fcfg_server_dao_get_env(FCFGMySQLContext *context, const char *env,
        FCFGEnvEntry *entry)
{
    FCFGEnvArray array;
    int result;

    if ((result=fcfg_server_dao_do_list_env(context, env, &array)) != 0) {
        return result;
    }
    if (array.count == 0) {
        return ENOENT;
    }

    entry->env.len = strlen(env);
    entry->env.str = (char *)env;
    entry->create_time = array.rows[0].create_time;
    entry->update_time = array.rows[0].update_time;

    fcfg_server_dao_free_env_array(&array);
    return 0;
}

void fcfg_server_dao_free_env_array(FCFGEnvArray *array)
{
    FCFGEnvEntry *current;
    FCFGEnvEntry  *end;
    
    if (array->rows == NULL) {
        return;
    }

    end = array->rows + array->count;
    for (current=array->rows; current<end; current++) {
        if (current->env.str != NULL) {
            free(current->env.str);
        }
    }

    free(array->rows);
    array->rows = NULL;
    array->count = 0;
}

static int fcfg_server_dao_store_max_version(MYSQL_STMT *stmt, int64_t *max_version)
{
    MYSQL_BIND result_binds[1];
    my_bool is_null;
    my_bool error;
    int row_count;

    *max_version = 0;

    memset(result_binds, 0, sizeof(result_binds));
    result_binds[0].buffer_type = MYSQL_TYPE_LONGLONG;
    result_binds[0].buffer = (char *)max_version;
    result_binds[0].is_null = &is_null;
    result_binds[0].error = &error;
    if (mysql_stmt_bind_result(stmt, result_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_result fail, error info: %s",
                __LINE__, mysql_stmt_error(stmt));
        return EINVAL;
    }

    if (mysql_stmt_execute(stmt) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_execute fail, error info: %s",
                __LINE__, mysql_stmt_error(stmt));
        return EINVAL;
    }

    if (mysql_stmt_store_result(stmt) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_store_result fail, error info: %s",
                __LINE__, mysql_stmt_error(stmt));
        return EINVAL;
    }

    row_count = mysql_stmt_num_rows(stmt);
    if (row_count == 0) {
        return 0;
    }

    if (mysql_stmt_fetch(stmt) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_fetch fail, error info: %s",
                __LINE__, mysql_stmt_error(stmt));
        return EFAULT;
    }

    return 0;
}

int fcfg_server_dao_max_config_version(FCFGMySQLContext *context,
            const char *env, int64_t *max_version)
{
    MYSQL_BIND select_binds[1];
    unsigned long env_len;

    env_len = strlen(env);
    memset(select_binds, 0, sizeof(select_binds));

    select_binds[0].buffer_type = MYSQL_TYPE_STRING;
    select_binds[0].buffer = (char *)env;
    select_binds[0].length = &env_len;
    if (mysql_stmt_bind_param(context->monitor.max_cfg_ver_stmt, select_binds) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call mysql_stmt_bind_param fail, error info: %s",
                __LINE__, mysql_stmt_error(context->monitor.max_cfg_ver_stmt));
        *max_version = 0;
        return EINVAL;
    }

    return fcfg_server_dao_store_max_version(context->monitor.max_cfg_ver_stmt,
            max_version);
}

int fcfg_server_dao_max_env_version(FCFGMySQLContext *context,
        int64_t *max_version)
{
    return fcfg_server_dao_store_max_version(context->monitor.max_env_ver_stmt,
            max_version);
}

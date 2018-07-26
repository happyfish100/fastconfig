
#include <sys/stat.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/sched_thread.h"
#include "common/fcfg_types.h"
#include "fcfg_server_global.h"
#include "fcfg_server_dao.h"
#include "fcfg_server_env.h"

static int fcfg_server_env_free_func(void *args)
{
    FCFGEnvArray *array;
    if (args == NULL) {
        return 0;
    }

    logInfo("file: "__FILE__", line: %d, "
            "env_array: %p freed", __LINE__, args);

    array = (FCFGEnvArray *)args;
    fcfg_server_dao_free_env_array(array);
    free(array);
    return 0;
}

static int fcfg_server_env_array_set(FCFGEnvArray *new_array)
{
    FCFGEnvArray *old_array;

    old_array = g_server_global_vars.env_array;
    g_server_global_vars.env_array = new_array;

    if (old_array != NULL) {
        logInfo("file: "__FILE__", line: %d, "
                "delay free env_array: %p", __LINE__, old_array);
        return sched_add_delay_task(fcfg_server_env_free_func,
                old_array, 60, false);
    }

    logInfo("file: "__FILE__", line: %d, "
            "config env count: %d", __LINE__, new_array->count);
    return 0;
}

int fcfg_server_env_load(struct fcfg_mysql_context *context)
{
    FCFGEnvArray *new_array;
    int result;
    new_array = (FCFGEnvArray *)malloc(sizeof(FCFGEnvArray));
    if (new_array == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, (int)sizeof(FCFGEnvArray));
        return ENOMEM;
    }

    if ((result=fcfg_server_dao_list_env(context, new_array)) != 0) {
        return result;
    }

    return fcfg_server_env_array_set(new_array);
}

int fcfg_server_env_init()
{
    FCFGMySQLContext mysql_context;
    int result;

    //to check mysql environment
    if ((result=fcfg_server_dao_init(&mysql_context)) != 0) {
        return result;
    }

    if ((result=fcfg_server_env_load(&mysql_context)) != 0) {
        return result;
    }

    fcfg_server_dao_destroy(&mysql_context);
    return 0;
}

void fcfg_server_env_destroy()
{
}

static int fcfg_server_env_compare(const void *p1, const void *p2)
{
    return strcmp(((FCFGEnvEntry *)p1)->env.str, ((FCFGEnvEntry *)p2)->env.str);
}

bool fcfg_server_env_exists(const char *env)
{
    FCFGEnvEntry targert;
    FCFGEnvEntry *found;

    targert.env.str = (char *)env;
    found = (FCFGEnvEntry *)bsearch(&targert, g_server_global_vars.env_array->rows,
            g_server_global_vars.env_array->count, sizeof(FCFGEnvEntry),
            fcfg_server_env_compare);
    return found != NULL;
}

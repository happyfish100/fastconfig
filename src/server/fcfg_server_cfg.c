
#include <sys/stat.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/fc_list.h"
#include "common/fcfg_types.h"
#include "fcfg_server_global.h"
#include "fcfg_server_dao.h"
#include "fcfg_server_cfg.h"

typedef struct {
    FCFGEnvContainer **envs;
    int count;
    int alloc;
    pthread_mutex_t lock;
} FCFGContainerArray;

static FCFGContainerArray container_array = {NULL, 0, 0};

static int fcfg_server_cfg_reload_by_env(struct fcfg_mysql_context *context,
        FCFGEnvContainer *container)
{
    int result;
    FCFGServerTaskArg *task_arg;
    struct fast_task_info *task;
    struct common_blocked_queue *push_queue;
    FCFGServerPushEvent *event;
    int64_t max_version;

    if ((result=fcfg_server_dao_max_config_version(context,
            container->env, &max_version)) != 0)
    {
        return result;
    }

    if (container->current_version == max_version) {
        return 0;
    }

    pthread_mutex_lock(&container->lock);
    fc_list_for_each_entry(task_arg, &container->head, subscribe) {
        task = fc_list_entry(task_arg, struct fast_task_info, arg);

        push_queue = &((FCFGServerContext *)task->thread_data->arg)->push_queue;

        //TODO
        event = NULL;  //TODO
        //event = mpool malloc  //TODO
        event->task = task;
        event->task_version = __sync_add_and_fetch(&task_arg->task_version, 0);
    }
    pthread_mutex_unlock(&container->lock);

    container->current_version = max_version;
    return 0;
}

int fcfg_server_cfg_reload(struct fcfg_mysql_context *context)
{
    int i;
    int result;

    for (i=0; i<container_array.count; i++) {
        if ((result=fcfg_server_cfg_reload_by_env(context,
                        container_array.envs[i])) != 0)
        {
            return result;
        }
    }

    return 0;
}

static int compare_env(const void *p1, const void *p2)
{
    return strcmp((*((FCFGEnvContainer **)p1))->env, (*((FCFGEnvContainer **)p2))->env);
}

static int check_alloc_container_array(FCFGContainerArray *array)
{
    FCFGEnvContainer **envs;
    int bytes;
    int alloc_size;

    if (array->alloc > array->count) {
        return 0;
    }

    alloc_size = array->alloc == 0 ? 8 : array->alloc * 2;
    bytes = sizeof(FCFGEnvContainer *) * alloc_size;
    envs = (FCFGEnvContainer **)malloc(bytes);
    if (envs == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, bytes);
        return ENOMEM;
    }

    memset(envs, 0, bytes);
    if (array->count > 0) {
        memcpy(envs, array->envs, sizeof(FCFGEnvContainer *) * array->count);
    }

    if (array->envs != NULL) {
        free(array->envs);
    }

    array->alloc = alloc_size;
    array->envs = envs;
    return 0;
}

int fcfg_server_cfg_init()
{
    return init_pthread_lock(&container_array.lock);
}

void fcfg_server_cfg_destroy()
{
}

static FCFGEnvContainer *fcfg_server_cfg_find_container(const char *env)
{
    FCFGEnvContainer **found;
    FCFGEnvContainer *target;
    FCFGEnvContainer temp;

    if (container_array.count == 0) {
        return NULL;
    }

    target = &temp;
    target->env = (char *)env;
    found = (FCFGEnvContainer **)bsearch(&target, container_array.envs,
            container_array.count, sizeof(FCFGEnvContainer *), compare_env);
    return (found != NULL) ? *found : NULL;
}

int fcfg_server_cfg_add_container(const char *env, FCFGEnvContainer **container)
{
    int result;
    if ((result=check_alloc_container_array(&container_array)) != 0) {
        return result;
    }

    *container = (FCFGEnvContainer *)malloc(sizeof(FCFGEnvContainer));
    if (*container == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__,
                (int)sizeof(FCFGEnvContainer));
        return ENOMEM;
    }

    memset(*container, 0, sizeof(FCFGEnvContainer));
    (*container)->env = strdup(env);
    init_pthread_lock(&(*container)->lock);
    FC_INIT_LIST_HEAD(&(*container)->head);
    container_array.envs[container_array.count++] = *container;
    if (container_array.count > 1) {
        qsort(container_array.envs, container_array.count,
                sizeof(FCFGEnvContainer *), compare_env);
    }

    return 0;
}

int fcfg_server_cfg_add_subscriber(const char *env, struct fast_task_info *task)
{
    FCFGEnvContainer *container;
    int result;

    pthread_mutex_lock(&container_array.lock);
    if ((container=fcfg_server_cfg_find_container(env)) == NULL) {
        result = fcfg_server_cfg_add_container(env, &container);
    } else {
        result = 0;
    }
    pthread_mutex_unlock(&container_array.lock);

    if (container != NULL) {
        FCFGServerTaskArg *task_arg;
        task_arg = (FCFGServerTaskArg *)task->arg;
        task_arg->container = container;

        pthread_mutex_lock(&container->lock);
        fc_list_add_tail(&task_arg->subscribe, &container->head);
        pthread_mutex_unlock(&container->lock);
    }
    return result;
}

void fcfg_server_cfg_remove_subscriber(struct fast_task_info *task)
{
    FCFGServerTaskArg *task_arg;
    task_arg = (FCFGServerTaskArg *)task->arg;
    if (task_arg->container != NULL) {
        pthread_mutex_lock(&task_arg->container->lock);
        fc_list_del_init(&task_arg->subscribe);
        pthread_mutex_unlock(&task_arg->container->lock);

        task_arg->container = NULL;
    }
}

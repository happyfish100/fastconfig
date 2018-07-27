
#include <sys/stat.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/fc_list.h"
#include "sf/sf_global.h"
#include "common/fcfg_types.h"
#include "fcfg_server_global.h"
#include "fcfg_server_dao.h"
#include "fcfg_server_cfg.h"

typedef struct {
    FCFGEnvPublisher **envs;
    int count;
    int alloc;
    pthread_mutex_t lock;
} FCFGPublisherArray;

static FCFGPublisherArray publisher_array = {NULL, 0, 0};

static int fcfg_server_cfg_free_config_array(void *args)
{
    fcfg_server_dao_free_config_array((FCFGConfigArray *)args);
    free(args);
    return 0;
}

static int check_alloc_config_array(FCFGConfigArray **array, const int inc)
{
    FCFGConfigArray *old_array;
    FCFGConfigArray *new_array;
    int target_count;
    int result;
    int bytes;

    target_count = (*array)->count + inc;
    if ((*array)->alloc >= target_count) {
        return 0;
    }

    new_array = (FCFGConfigArray *)malloc(sizeof(FCFGConfigArray));
    if (new_array == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail",
                __LINE__, (int)sizeof(FCFGConfigArray));
        return ENOMEM;
    }

    new_array->alloc = ((*array)->alloc > 0) ? (*array)->alloc : 8;
    while (new_array->alloc < target_count) {
        new_array->alloc *= 2;
    }

    bytes = sizeof(FCFGConfigEntry) * new_array->alloc;
    new_array->rows = (FCFGConfigEntry *)malloc(bytes);
    if (new_array->rows == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, bytes);
        return ENOMEM;
    }

    new_array->count = 0;
    if ((result=fcfg_server_dao_copy_config_array(*array, new_array)) != 0) {
        return result;
    }

    old_array = *array;
    *array = new_array;
    return sched_add_delay_task(fcfg_server_cfg_free_config_array,
            old_array, 10 * g_sf_global_vars.network_timeout, false);
}

static int fcfg_server_cfg_reload_config_incr(struct fcfg_mysql_context *context,
        FCFGEnvPublisher *publisher)
{
    const int limit = 1024 * 1024;
    FCFGConfigArray inc_array;
    int result;

    if ((result=fcfg_server_dao_list_config_by_env_and_version(context,
                    publisher->env, publisher->current_version, limit,
                    &inc_array)) != 0)
    {
        return result;
    }

    if (inc_array.count == 0) {
        return 0;
    }

    if (publisher->config_array->count == 0) {
        *(publisher->config_array) = inc_array;
        return 0;
    }

    if ((result=check_alloc_config_array(&publisher->config_array,
                    inc_array.count)) == 0)
    {
        result = fcfg_server_dao_copy_config_array(&inc_array,
                publisher->config_array);
    }

    fcfg_server_dao_free_config_array(&inc_array);
    return result;
}

static int fcfg_server_cfg_reload_config_all(struct fcfg_mysql_context *context,
        FCFGEnvPublisher *publisher)
{
    const int64_t version = 0;
    const int limit = 1024 * 1024;
    FCFGConfigArray *old_array;
    FCFGConfigArray *new_array;
    int result;

    new_array = (FCFGConfigArray *)malloc(sizeof(FCFGConfigArray));
    if (new_array == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail",
                __LINE__, (int)sizeof(FCFGConfigArray));
        return ENOMEM;
    }

    if ((result=fcfg_server_dao_list_config_by_env_and_version(context,
                    publisher->env, version, limit, new_array)) != 0)
    {
        return result;
    }

    old_array = publisher->config_array;
    publisher->config_array = new_array;
    return sched_add_delay_task(fcfg_server_cfg_free_config_array,
            old_array, 10 * g_sf_global_vars.network_timeout, false);
}

static int fcfg_server_cfg_notify(FCFGEnvPublisher *publisher)
{
    FCFGServerTaskArg *task_arg;
    struct fast_task_info *task;
    struct common_blocked_queue *push_queue;
    FCFGServerPushEvent *event;
    int result;

    result = 0;
    pthread_mutex_lock(&publisher->lock);
    fc_list_for_each_entry(task_arg, &publisher->head, subscribe) {
        task = (struct fast_task_info *)((char *)task_arg - ALIGNED_TASK_INFO_SIZE);
        push_queue = &((FCFGServerContext *)task->thread_data->arg)->push_queue;

        event = (FCFGServerPushEvent *)fast_mblock_alloc_object(
                &publisher->event_allocator);
        if (event == NULL) {
            result = ENOMEM;
            break;
        }

        event->task = task;
        event->task_version = __sync_add_and_fetch(&task_arg->task_version, 0);
        if ((result=common_blocked_queue_push(push_queue, event)) != 0) {
            break;
        }
    }
    pthread_mutex_unlock(&publisher->lock);
    return result;
}

static int fcfg_server_cfg_reload_by_env_incr(struct fcfg_mysql_context *context,
        FCFGEnvPublisher *publisher)
{
    int result;
    int64_t max_version;

    if ((result=fcfg_server_dao_max_config_version(context,
            publisher->env, &max_version)) != 0)
    {
        return result;
    }

    if (publisher->current_version >= max_version) {
        return 0;
    }

    if ((result=fcfg_server_cfg_reload_config_incr(context, publisher)) != 0) {
        return result;
    }

    if (publisher->config_array->count > 0) {
        publisher->current_version = publisher->config_array->rows
            [publisher->config_array->count - 1].version;
    } else {
        publisher->current_version = max_version;
    }
    publisher->config_stat.version_changed.total_count++;

    return fcfg_server_cfg_notify(publisher);
}

static int fcfg_server_cfg_reload_by_env_all(struct fcfg_mysql_context *context,
        FCFGEnvPublisher *publisher)
{
    int result;
    int64_t old_version;

    if ((result=fcfg_server_cfg_reload_config_all(context, publisher)) != 0) {
        return result;
    }

    old_version = publisher->current_version;
    if (publisher->config_array->count > 0) {
        publisher->current_version = publisher->config_array->rows
            [publisher->config_array->count - 1].version;
    } else {
        publisher->current_version = 0;
    }

    if (publisher->current_version > old_version) {
        result = fcfg_server_cfg_notify(publisher);
    }
    return result;
}

int fcfg_server_cfg_reload(struct fcfg_mysql_context *context)
{
    FCFGEnvPublisher *publisher;
    FCFGServerReloadAllConfigsPolicy *reload_all_policy;
    int i;
    int result;
    int changed_count;

    reload_all_policy = &g_server_global_vars.reload_all_configs_policy;
    for (i=0; i<publisher_array.count; i++) {
        publisher = publisher_array.envs[i];
        changed_count = publisher->config_stat.version_changed.total_count -
            publisher->config_stat.version_changed.last_count;
        if ((changed_count >= reload_all_policy->min_version_changed &&
                g_current_time - publisher->config_stat.last_reload_all_time >
                reload_all_policy->min_interval) ||
                (publisher->config_stat.reload_all && changed_count > 0))
        {
            publisher->config_stat.reload_all = false;
            publisher->config_stat.version_changed.last_count =
                publisher->config_stat.version_changed.total_count;
            publisher->config_stat.last_reload_all_time = g_current_time;
            result = fcfg_server_cfg_reload_by_env_all(context, publisher);
        } else {
            result = fcfg_server_cfg_reload_by_env_incr(context, publisher);
        }

        if (result != 0) {
            return result;
        }
    }

    return 0;
}

static int compare_env(const void *p1, const void *p2)
{
    return strcmp((*((FCFGEnvPublisher **)p1))->env, (*((FCFGEnvPublisher **)p2))->env);
}

static int check_alloc_publisher_array(FCFGPublisherArray *array)
{
    FCFGEnvPublisher **envs;
    int bytes;
    int alloc_size;

    if (array->alloc > array->count) {
        return 0;
    }

    alloc_size = array->alloc == 0 ? 8 : array->alloc * 2;
    bytes = sizeof(FCFGEnvPublisher *) * alloc_size;
    envs = (FCFGEnvPublisher **)malloc(bytes);
    if (envs == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, bytes);
        return ENOMEM;
    }

    memset(envs, 0, bytes);
    if (array->count > 0) {
        memcpy(envs, array->envs, sizeof(FCFGEnvPublisher *) * array->count);
    }

    if (array->envs != NULL) {
        free(array->envs);
    }

    array->alloc = alloc_size;
    array->envs = envs;
    return 0;
}

static int set_reload_all_flag(void *args)
{
    int i;
    pthread_mutex_lock(&publisher_array.lock);
    for (i=0; i<publisher_array.count; i++) {
        publisher_array.envs[i]->config_stat.reload_all = true;
    }
    pthread_mutex_unlock(&publisher_array.lock);

    return 0;
}

int fcfg_server_cfg_init()
{
#define SCHEDULE_ENTRIES_COUNT 1

    ScheduleArray scheduleArray;
    ScheduleEntry scheduleEntries[SCHEDULE_ENTRIES_COUNT];
    int result;
    int id;

    scheduleArray.entries = scheduleEntries;
    scheduleArray.count = 1;

    memset(scheduleEntries, 0, sizeof(scheduleEntries));

    id = sched_generate_next_id();
    INIT_SCHEDULE_ENTRY(scheduleEntries[0], id, 0, 0, 0,
            g_server_global_vars.reload_all_configs_policy.max_interval,
            set_reload_all_flag, NULL);

    if ((result=sched_add_entries(&scheduleArray)) != 0) {
        return result;
    }
    return init_pthread_lock(&publisher_array.lock);
}

void fcfg_server_cfg_destroy()
{
}

static FCFGEnvPublisher *fcfg_server_cfg_find_publisher(const char *env)
{
    FCFGEnvPublisher **found;
    FCFGEnvPublisher *target;
    FCFGEnvPublisher temp;

    if (publisher_array.count == 0) {
        return NULL;
    }

    target = &temp;
    target->env = (char *)env;
    found = (FCFGEnvPublisher **)bsearch(&target, publisher_array.envs,
            publisher_array.count, sizeof(FCFGEnvPublisher *), compare_env);
    return (found != NULL) ? *found : NULL;
}

int fcfg_server_cfg_add_publisher(const char *env, FCFGEnvPublisher **publisher)
{
    int result;
    if ((result=check_alloc_publisher_array(&publisher_array)) != 0) {
        return result;
    }

    *publisher = (FCFGEnvPublisher *)malloc(sizeof(FCFGEnvPublisher));
    if (*publisher == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__,
                (int)sizeof(FCFGEnvPublisher));
        return ENOMEM;
    }

    memset(*publisher, 0, sizeof(FCFGEnvPublisher));
    (*publisher)->env = strdup(env);
    init_pthread_lock(&(*publisher)->lock);

    (*publisher)->config_array = (FCFGConfigArray *)malloc(sizeof(FCFGConfigArray));
    if ((*publisher)->config_array == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail",
                __LINE__, (int)sizeof(FCFGConfigArray));
        free(*publisher);
        *publisher = NULL;
        return ENOMEM;
    }
    (*publisher)->config_array->alloc = (*publisher)->config_array->count = 0;
    (*publisher)->config_array->rows = NULL;
   
    if ((result=fast_mblock_init_ex(&(*publisher)->event_allocator,
                    sizeof(FCFGServerPushEvent), 1024, NULL, false)) != 0)
    {
        free((*publisher)->config_array);
        free(*publisher);
        *publisher = NULL;
        return result;
    }

    FC_INIT_LIST_HEAD(&(*publisher)->head);
    publisher_array.envs[publisher_array.count++] = *publisher;
    if (publisher_array.count > 1) {
        qsort(publisher_array.envs, publisher_array.count,
                sizeof(FCFGEnvPublisher *), compare_env);
    }

    return 0;
}

int fcfg_server_cfg_add_subscriber(const char *env, struct fast_task_info *task)
{
    FCFGEnvPublisher *publisher;
    int result;

    pthread_mutex_lock(&publisher_array.lock);
    if ((publisher=fcfg_server_cfg_find_publisher(env)) == NULL) {
        result = fcfg_server_cfg_add_publisher(env, &publisher);
    } else {
        result = 0;
    }
    pthread_mutex_unlock(&publisher_array.lock);

    if (publisher != NULL) {
        FCFGServerTaskArg *task_arg;
        task_arg = (FCFGServerTaskArg *)task->arg;
        task_arg->publisher = publisher;

        pthread_mutex_lock(&publisher->lock);
        fc_list_add_tail(&task_arg->subscribe, &publisher->head);
        pthread_mutex_unlock(&publisher->lock);
    }
    return result;
}

void fcfg_server_cfg_remove_subscriber(struct fast_task_info *task)
{
    FCFGServerTaskArg *task_arg;
    task_arg = (FCFGServerTaskArg *)task->arg;
    if (task_arg->publisher != NULL) {
        pthread_mutex_lock(&task_arg->publisher->lock);
        fc_list_del_init(&task_arg->subscribe);
        pthread_mutex_unlock(&task_arg->publisher->lock);

        task_arg->publisher = NULL;
    }
}

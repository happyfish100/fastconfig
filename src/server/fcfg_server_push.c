//fcfg_server_push.c

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "fastcommon/logger.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/ioevent_loop.h"
#include "sf/sf_util.h"
#include "sf/sf_func.h"
#include "sf/sf_nio.h"
#include "sf/sf_global.h"
#include "common/fcfg_proto.h"
#include "fcfg_server_types.h"
#include "fcfg_server_global.h"
#include "fcfg_server_func.h"
#include "fcfg_server_dao.h"
#include "fcfg_server_env.h"
#include "fcfg_server_cfg.h"
#include "fcfg_server_push.h"

static struct fcfg_mysql_context mysql_context;

static void *fcfg_server_push_entrance(void *arg)
{
    int usleep_time;
    int64_t count = 0;

    usleep_time = g_server_global_vars.reload_interval_ms * 1000;
    while (g_sf_global_vars.continue_flag) {
        if (fcfg_server_env_load(&mysql_context) != 0) {
            sleep(1);
        }

        if (fcfg_server_cfg_reload(&mysql_context) != 0) {
            sleep(1);
        }

        usleep(usleep_time);
        if (count++ % 100 == 0) {
            logInfo("push loop: %"PRId64, count);
        }
    }

    return NULL;
}

int fcfg_server_push_init()
{
    int result;
    pthread_attr_t thread_attr;
    pthread_t tid;

    if ((result=fcfg_server_env_init()) != 0) {
        return result;
    }

    if ((result=fcfg_server_cfg_init()) != 0) {
        return result;
    }

    if ((result=fcfg_server_dao_init(&mysql_context)) != 0) {
        return result;
    }

    if ((result=init_pthread_attr(&thread_attr,
                    g_sf_global_vars.thread_stack_size)) != 0)
    {
        return result;
    }

    if ((result=pthread_create(&tid, &thread_attr,
                    fcfg_server_push_entrance, NULL)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "create thread failed, errno: %d, error info: %s",
                __LINE__, result, strerror(result));
        return result;
    }

    pthread_attr_destroy(&thread_attr);
    return 0;
}

int fcfg_server_push_destroy()
{
    return 0;
}

static int find_config_version_closest_less_equal(FCFGConfigArray *array,
        int64_t target_version)
{
    int low;
    int high;
    int mid;

    if (array->count == 0) {
        return -1;
    }

    low = 0;
    high = array->count - 1;
    while (low <= high) {
        mid = (low + high) / 2;
        if (array->rows[mid].version > target_version) {
            high = mid - 1;
        } else if (array->rows[mid].version < target_version) {
            low = mid + 1;
        } else {
            return mid;
        }
    }

    if (array->rows[high].version < target_version) {
        return high;
    } else {
        return high - 1;
    }
}

static int fcfg_server_do_push_configs(struct fast_task_info *task)
{
#define CONFIG_RECORD_SIZE(config) \
    (sizeof(FCFGProtoPushConfigBodyPart) + config->name.len + config->value.len)

    FCFGConfigMessageQueue *msg_queue;
    FCFGConfigEntry *config;
    FCFGProtoPushConfigHeader *header_part;
    FCFGProtoPushConfigBodyPart *body_part;
    int result;
    int start_offset;
    int record_size;
    int expect_size;

    header_part = (FCFGProtoPushConfigHeader *)(task->data + sizeof(FCFGProtoHeader));
    task->length = sizeof(FCFGProtoHeader) + sizeof(FCFGProtoPushConfigHeader);

    msg_queue = &((FCFGServerTaskArg *)task->arg)->msg_queue;
    config = msg_queue->config_array->rows + msg_queue->offset;
    record_size = CONFIG_RECORD_SIZE(config);
    expect_size = task->length + record_size;
    if (expect_size > task->size) {
        if ((result=free_queue_set_buffer_size(task, expect_size)) != 0) {
            return result;
        }
    }

    start_offset = msg_queue->offset;
    msg_queue = &((FCFGServerTaskArg *)task->arg)->msg_queue;
    while (msg_queue->offset < msg_queue->config_array->count) {
        config = msg_queue->config_array->rows + msg_queue->offset;
        record_size = CONFIG_RECORD_SIZE(config);
        expect_size = task->length + record_size;
        if (expect_size > task->size) {
            break;
        }

        body_part = (FCFGProtoPushConfigBodyPart *)(task->data + task->length);
        body_part->status = config->status;
        body_part->name_len = config->name.len;
        int2buff(config->value.len, body_part->value_len);
        long2buff(config->version, body_part->version);
        int2buff(config->create_time, body_part->create_time);
        int2buff(config->update_time, body_part->update_time);
        memcpy(body_part->name, config->name.str, config->name.len);
        memcpy(body_part->name + config->name.len, config->value.str,
                config->value.len);

        task->length += record_size;
        msg_queue->offset++;
    }

    short2buff(msg_queue->offset - start_offset, header_part->count);
    msg_queue->agent_cfg_version = msg_queue->config_array->rows
        [msg_queue->offset - 1].version;

    return sf_send_add_event(task);
}

int fcfg_server_push_configs(struct fast_task_info *task)
{
    FCFGServerTaskArg *task_arg;
    FCFGConfigMessageQueue *msg_queue;
    int config_count;

    task_arg = (FCFGServerTaskArg *)task->arg;
    msg_queue = &task_arg->msg_queue;

    if (msg_queue->config_array == NULL || (msg_queue->config_array->version !=
                task_arg->publisher->config_array->version))
    {
        msg_queue->config_array = task_arg->publisher->config_array;
        config_count = msg_queue->config_array->count;
        if (config_count > 0) {
            if (msg_queue->config_array->rows[config_count - 1]
                    .version == msg_queue->agent_cfg_version)
            {
                msg_queue->offset = config_count;
            } else {
                msg_queue->offset = find_config_version_closest_less_equal(
                        msg_queue->config_array, msg_queue->agent_cfg_version) + 1;
            }
        } else {
            msg_queue->offset = 0;
        }
    }

    if (msg_queue->offset >= msg_queue->config_array->count) {
        return 0;
    }

    task_arg->waiting_type |= FCFG_SERVER_TASK_WAITING_PUSH_RESP;
    return fcfg_server_do_push_configs(task);
}

int fcfg_server_thread_loop(struct nio_thread_data *thread_data)
{
    struct common_blocked_queue *push_queue;
    FCFGServerPushEvent *event;
    FCFGServerTaskArg *task_arg;
    int64_t task_version;

    push_queue = &((FCFGServerContext *)thread_data->arg)->push_queue;

    while ((event=(FCFGServerPushEvent *)common_blocked_queue_try_pop(
                    push_queue)) != NULL)
    {
        task_arg = (FCFGServerTaskArg *)event->task->arg;

        task_version = __sync_add_and_fetch(&task_arg->task_version, 0);
        if (event->task_version != task_version) {
            logInfo("file: "__FILE__", line: %d, "
                    "task version changed, current task version: %"PRId64", "
                    "task version in event: %"PRId64, __LINE__,
                    task_version, event->task_version);
            continue;
        }

        if ((sf_client_sock_in_read_stage(event->task) && event->task->offset == 0) &&
                (task_arg->waiting_type & FCFG_SERVER_TASK_WAITING_PUSH_RESP) == 0)
        {
            fcfg_server_push_configs(event->task);
        }
    }

    return 0;
}

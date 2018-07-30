#ifndef _FCFG_SERVER_TYPES_H
#define _FCFG_SERVER_TYPES_H

#include <time.h>
#include <pthread.h>
#include "fastcommon/common_define.h"
#include "fastcommon/common_blocked_queue.h"
#include "fastcommon/fast_task_queue.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/fc_list.h"
#include "fcfg_server_dao.h"

#define FCFG_SERVER_DEFAULT_INNER_PORT  20000
#define FCFG_SERVER_DEFAULT_OUTER_PORT  20000

#define FCFG_SERVER_DEFAULT_RELOAD_INTERVAL  500

typedef struct fcfg_server_context {
    FCFGMySQLContext mysql_context;
    struct common_blocked_queue push_queue;
} FCFGServerContext;

typedef struct fcfg_env_publisher {
    char *env;
    int64_t current_version;
    struct fc_list_head head;   //subscribe task double chain
    pthread_mutex_t lock;
    struct fast_mblock_man event_allocator;
    FCFGConfigArray *config_array;

    struct {
        time_t last_reload_all_time;
        struct {
            int64_t total_count;
            int64_t last_count;
        } version_changed;
        bool reload_all;
    } config_stat;
} FCFGEnvPublisher;

typedef struct fcfg_config_message_queue {
    int64_t agent_cfg_version;
    FCFGConfigArray *config_array;
    int offset;
} FCFGConfigMessageQueue;

#define FCFG_SERVER_TASK_WAITING_REQUEST          0
#define FCFG_SERVER_TASK_WAITING_PUSH_RESP        1
#define FCFG_SERVER_TASK_WAITING_ACTIVE_TEST_RESP 2

typedef struct fcfg_server_task_arg {
    int64_t task_version;

    struct fc_list_head subscribe;
    FCFGEnvPublisher *publisher;

    FCFGConfigMessageQueue msg_queue;

    int waiting_type;
} FCFGServerTaskArg;

typedef struct fcfg_server_push_event {
    struct fast_task_info *task;
    int64_t task_version;
} FCFGServerPushEvent;

#endif

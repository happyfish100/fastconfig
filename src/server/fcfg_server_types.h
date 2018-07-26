#ifndef _FCFG_SERVER_TYPES_H
#define _FCFG_SERVER_TYPES_H

#include "fastcommon/common_define.h"
#include "fastcommon/common_blocked_queue.h"
#include "fastcommon/fast_task_queue.h"
#include "fastcommon/fc_list.h"
#include "fcfg_server_dao.h"

typedef struct fcfg_server_context {
    FCFGMySQLContext mysql_context;
    struct common_blocked_queue push_queue;
} FCFGServerContext;

typedef struct fcfg_server_task_arg {
    int64_t agent_cfg_version;
    int64_t task_version;

    struct fc_list_head subscribe;
} FCFGServerTaskArg;

typedef struct fcfg_server_push_event {
    struct fast_task_info *task;
    int64_t task_version;
} FCFGServerPushEvent;

#endif

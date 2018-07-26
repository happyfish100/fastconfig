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

int fcfg_server_thread_loop(struct nio_thread_data *thread_data)
{
    return 0;
}

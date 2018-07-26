#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/process_ctrl.h"
#include "fastcommon/logger.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/sched_thread.h"
#include "sf/sf_global.h"
#include "sf/sf_nio.h"
#include "sf/sf_service.h"
#include "sf/sf_util.h"
#include "common/fcfg_proto.h"
#include "common/fcfg_types.h"
#include "fcfg_server_types.h"
#include "fcfg_server_func.h"
#include "fcfg_server_handler.h"
#include "fcfg_server_dao.h"
#include "fcfg_server_env.h"
#include "fcfg_server_push.h"

static bool daemon_mode = true;
static int setup_server_env(const char *config_filename);

static int test();

int main(int argc, char *argv[])
{
    char *config_filename;
    char *action;
    char g_pid_filename[MAX_PATH_SIZE];
    pthread_t schedule_tid;
    int wait_count;
    bool stop;
    int r;
    failvars;

    stop = false;
    if (argc < 2) {
        sf_usage(argv[0]);
        return 1;
    }
    config_filename = argv[1];
    log_init2();

    r = get_base_path_from_conf_file(config_filename, g_sf_global_vars.base_path,
                                     sizeof(g_sf_global_vars.base_path));
    gofailif(r, "base path error");

    snprintf(g_pid_filename, sizeof(g_pid_filename), 
             "%s/fcfg_serverd.pid", g_sf_global_vars.base_path);

    sf_parse_daemon_mode_and_action(argc, argv, &daemon_mode, &action);
    r = process_action(g_pid_filename, action, &stop);
    if (r == EINVAL) {
        sf_usage(argv[0]);
        log_destroy();
        return 1;
    }
    gofailif(r, "process arg error");

    if (stop) {
        log_destroy();
        return 0;
    }

    r = setup_server_env(config_filename);
    gofailif(r,"");

    r = sf_startup_schedule(&schedule_tid);
    gofailif(r,"");

    r = sf_socket_server();
    gofailif(r, "socket server error");
    r = write_to_pid_file(g_pid_filename);
    gofailif(r, "write pid error");

    r = fcfg_server_handler_init();
    gofailif(r,"server handler init error");

    r = fcfg_server_env_init();
    gofailif(r,"server env init error");

    fcfg_proto_init();

    r = sf_service_init(fcfg_server_alloc_thread_extra_data,
            fcfg_server_thread_loop,
            NULL, fcfg_proto_set_body_length, fcfg_server_deal_task,
            fcfg_server_task_finish_cleanup, NULL, 100, sizeof(FCFGProtoHeader),
            sizeof(FCFGServerTaskArg));
    gofailif(r,"service init error");
    sf_set_remove_from_ready_list(false);


    test();

    sf_accept_loop();
    if (g_schedule_flag) {
        pthread_kill(schedule_tid, SIGINT);
    }
    wait_count = 0;
    while ((g_worker_thread_count != 0) || g_schedule_flag) {
        usleep(10000);
        if (++wait_count > 1000) {
            lwarning("waiting timeout, exit!");
            break;
        }
    }

    linfo("destroying.");
    sf_service_destroy();
    delete_pid_file(g_pid_filename);
    linfo("program exit normally.");
    log_destroy();
    return 0;

FAIL_:
    logfail();
    lcrit("program exit abnomally");
    log_destroy();
    return eres;
}

static int setup_server_env(const char *config_filename)
{
    int result;

    sf_set_current_time();

    result = fcfg_server_load_config(config_filename);
    if (result != 0) {
        fprintf(stderr, "load from conf file %s fail, "
                "erro no: %d, error info: %s",
                config_filename, result, strerror(result));
        return result;
    }

    if (daemon_mode) {
        daemon_init(false);
    }
    umask(0);

    result = sf_setup_signal_handler();

    log_set_cache(true);
    return result;
}

static int test()
{
    FCFGMySQLContext context;
    FCFGConfigArray rows;
    int result;
    const char *env = "test";
    const char *name = "system.server_level";
    const char *value = "5";
    const int64_t version = 64;
    const int offset = 0;
    const int limit = 5;
    int64_t max_env_version = 0;
    int64_t max_cfg_version = 0;

    if ((result=fcfg_server_dao_init(&context)) != 0) {
        return result;
    }

    result = fcfg_server_dao_set_config(&context, env, name, value);
    result = fcfg_server_dao_set_config(&context, env, name, value);
    result = fcfg_server_dao_set_config(&context, env, name, value);

    logInfo("fcfg_server_dao_list_config_by_env_and_version output:");
    fcfg_server_dao_list_config_by_env_and_version(&context,
            env, version, limit, &rows);
    fcfg_server_dao_free_config_array(&rows);

    logInfo("fcfg_server_dao_list_config_by_env_and_version output:");
    fcfg_server_dao_list_config_by_env_and_version(&context,
            env, version, limit, &rows);
    fcfg_server_dao_free_config_array(&rows);

    /*
    logInfo("delete: %d", fcfg_server_dao_del_config(&context, env, name));
    logInfo("delete: %d", fcfg_server_dao_del_config(&context, env, name));
    logInfo("delete: %d", fcfg_server_dao_del_config(&context, env, name));
    */

    fcfg_server_dao_max_env_version(&context, &max_env_version);
    fcfg_server_dao_max_config_version(&context, &max_cfg_version);

    fcfg_server_dao_max_env_version(&context, &max_env_version);
    fcfg_server_dao_max_config_version(&context, &max_cfg_version);
    logInfo("max_env_version: %"PRId64", max_cfg_version: %"PRId64,
            max_env_version, max_cfg_version);

    logInfo("fcfg_server_dao_search_config output:");
    name = "system%";
    fcfg_server_dao_search_config(&context,
            env, name, offset, limit, &rows);
    fcfg_server_dao_free_config_array(&rows);

    fcfg_server_dao_destroy(&context);
    return result;
}

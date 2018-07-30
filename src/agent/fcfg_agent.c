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
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/process_ctrl.h"
#include "fastcommon/logger.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/sched_thread.h"
#include "sf/sf_global.h"
#include "sf/sf_service.h"
#include "sf/sf_util.h"
#include "common/fcfg_proto.h"
#include "fastcommon/sockopt.h"
#include "fcfg_agent_handler.h"
#include "fcfg_agent_func.h"
#include "fcfg_agent_global.h"

static bool show_usage = false;
static bool daemon_mode = true;
FCFGAgentGlobalVars g_agent_global_vars;
static int setup_server_env(const char *config_filename);
static void usage(char *program)
{
    fprintf(stderr, "Usage: %s options, the options as:\n"
            "\t -h help\n"
            "\t -c <config-filename>\n"
            "\n", program);
}

static void parse_args(int argc, char **argv)
{
    int ch;
    int found = 0;

    while ((ch = getopt(argc, argv, "hc:")) != -1) {
        found = 1;
        switch (ch) {
            case 'c':
                g_agent_global_vars.config_file = optarg;
                break;
            case 'h':
            default:
                show_usage = true;
                break;
        }
    }
    if (found == 0) {
        show_usage = true;
    }
}

int main (int argc, char **argv)
{
    char g_pid_filename[MAX_PATH_SIZE];
    pthread_t schedule_tid;
    int wait_count = 0;
    char *action;
    bool stop;
    int r;
    failvars;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    memset(&g_agent_global_vars, 0, sizeof(FCFGAgentGlobalVars));
    parse_args(argc, argv);
    if (show_usage) {
        usage(argv[0]);
        return 0;
    }
    log_init2();
    log_set_use_file_write_lock(true);

    r = get_base_path_from_conf_file(g_agent_global_vars.config_file, g_sf_global_vars.base_path,
            sizeof(g_sf_global_vars.base_path));

    gofailif (r, "get base path fail");
    snprintf(g_pid_filename, sizeof(g_pid_filename),
            "%s/fcfg_agent.pid", g_sf_global_vars.base_path);

    sf_parse_daemon_mode_and_action(argc, argv, &daemon_mode, &action);
    r = process_action(g_pid_filename, action, &stop);
    if (r == EINVAL) {
        usage(argv[0]);
        log_destroy();
        return 1;
    }
    gofailif(r, "process arg error");

    if (stop) {
        log_destroy();
        return 0;
    }

    r = setup_server_env(g_agent_global_vars.config_file);
     gofailif(r, "setup_server_env fail");
     r = write_to_pid_file(g_pid_filename);
     gofailif(r, "write pid error");

    r = sf_startup_schedule(&schedule_tid);
    gofailif(r, "sf_startup_schedule fail");

    fcfg_agent_wait_config_server_loop();

    if (g_schedule_flag) {
        pthread_kill(schedule_tid, SIGINT);
    }
    while (g_schedule_flag) {
        usleep(10000);
        if (++wait_count > 1000) {
            lwarning("waiting timeout, exit!");
            break;
        }
    }
FAIL_:
    delete_pid_file(g_pid_filename);
    log_destroy();
    return 0;
}

static int setup_server_env(const char *config_filename)
{
    int result;

    sf_set_current_time();

    result = fcfg_agent_load_config(config_filename);
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
    returnif(result);

    result = fcfg_agent_shm_init();
    log_set_cache(true);
    return 0;
}

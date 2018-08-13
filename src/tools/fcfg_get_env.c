#include<stdio.h>
#include "fcfg_admin.h"
#include "fastcommon/logger.h"
#include "fcfg_func.h"

static bool show_usage = false;
char *config_file = NULL;
char *env = NULL;
static void usage(char *program)
{
    fprintf(stderr, "Usage: %s options, the options as:\n"
            "\t -h help\n"
            "\t -c <config-filename>\n"
            "\t -e <env>\n"
            "\n", program);
}
static void parse_args(int argc, char **argv)
{
    int ch;
    int found = 0;

    while ((ch = getopt(argc, argv, "hc:e:")) != -1) {
        found = 1;
        switch (ch) {
            case 'c':
                config_file = optarg;
                break;
            case 'e':
                env = optarg;
                break;
            case 'h':
            default:
                show_usage = true;
                break;
        }
    }
    if (found == 0 ||
        config_file == NULL ||
        env == NULL) {
        show_usage = true;
    }
}

int main (int argc, char **argv)
{
    int ret;
    struct fcfg_context fcfg_context;
    FCFGEnvArray array;
    memset(&array, 0, sizeof(FCFGEnvArray));
    if (argc < 5) {
        usage(argv[0]);
        return 0;
    }
    parse_args(argc, argv);
    if (show_usage) {
        usage(argv[0]);
        return 0;
    }
    log_init2();

    ret = fcfg_admin_init_from_file(&fcfg_context, config_file);
    if (ret) {
        goto END;
    }
    ret = fcfg_admin_env_get(&fcfg_context, env, &array);
    if (ret == 0) {
        fcfg_print_env_array(&array);
    }
END:
    log_destroy();
    fcfg_free_env_array(&array);
    fcfg_admin_destroy(&fcfg_context);
    return ret;
}
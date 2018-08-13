#ifndef _FCFG_ADMIN_H
#define _FCFG_ADMIN_H

#include "fastcommon/multi_socket_client.h"
#include "fcfg_admin_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int fcfg_admin_init_from_file (struct fcfg_context *fcfg_context,
        const char *config_filename);
int fcfg_admin_destroy (struct fcfg_context *fcfg_context);

int fcfg_admin_config_set (struct fcfg_context *fcfg_context,
        const char *env, const char *config_name, const char *config_value);    
int fcfg_admin_config_get (struct fcfg_context *fcfg_context,
        const char *env, const char *config_name, FCFGConfigInfoArray *array);
int fcfg_admin_config_del (struct fcfg_context *fcfg_context,
        const char *env, const char *config_name);
int fcfg_admin_config_list (struct fcfg_context *fcfg_context,
        const char *env, const char *config_name, const int limit, FCFGConfigInfoArray *array);

int fcfg_admin_env_add (struct fcfg_context *fcfg_context, const char *env);
int fcfg_admin_env_get (struct fcfg_context *fcfg_context, const char *env,
        FCFGEnvInfoArray *array);
int fcfg_admin_env_del (struct fcfg_context *fcfg_context, const char *env);
int fcfg_admin_env_list (struct fcfg_context *fcfg_context,
        FCFGEnvInfoArray *array);
void fcfg_print_env_array (FCFGEnvInfoArray *array);
void fcfg_print_config_array (FCFGConfigInfoArray *array);
void fcfg_free_env_info_array(FCFGEnvInfoArray *array);
void fcfg_free_config_info_array(FCFGConfigInfoArray *array);

#ifdef __cplusplus
}
#endif

#endif

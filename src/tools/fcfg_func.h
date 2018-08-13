#ifndef _FCFG_FUNC_H
#define _FCFG_FUNC_H

#ifdef __cplusplus
extern "C" {
#endif

void fcfg_print_env_array (FCFGEnvArray *array);
void fcfg_print_config_array (FCFGConfigArray *array);
extern void fcfg_free_env_array(FCFGEnvArray *array);
extern void fcfg_free_config_array(FCFGConfigArray *array);

#ifdef __cplusplus
}
#endif

#endif

#ifndef _FCFG_ADMIN_H
#define _FCFG_ADMIN_H

#ifdef __cplusplus
extern "C" {
#endif

int fcfg_admin_config_set (int argc, char **argv);    
int fcfg_admin_config_get (int argc, char **argv);
int fcfg_admin_config_del (int argc, char **argv);
int fcfg_admin_config_list (int argc, char **argv);
int fcfg_admin_env_add (int argc, char **argv);
int fcfg_admin_env_get (int argc, char **argv);
int fcfg_admin_env_del (int argc, char **argv);
int fcfg_admin_env_list (int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif

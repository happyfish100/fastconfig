
#ifndef _FCFG_SERVER_CFG_H
#define _FCFG_SERVER_CFG_H

#include "common/fcfg_types.h"
#include "fcfg_server_types.h"

#ifdef __cplusplus
extern "C" {
#endif

    int fcfg_server_cfg_init();

    void fcfg_server_cfg_destroy();

    int fcfg_server_cfg_reload();

#ifdef __cplusplus
}
#endif

#endif

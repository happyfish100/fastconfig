
#ifndef _FCFG_SERVER_DAO_H
#define _FCFG_SERVER_DAO_H

#include <mysql.h>

#ifdef __cplusplus
extern "C" {
#endif

    int fcfg_server_dao_init(MYSQL *mysql);

    void fcfg_server_dao_destroy(MYSQL *mysql);

#ifdef __cplusplus
}
#endif

#endif

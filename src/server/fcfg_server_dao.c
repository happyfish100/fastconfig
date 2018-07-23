
#include <sys/stat.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "sf/sf_global.h"
#include "sf/sf_service.h"
#include "common/fcfg_types.h"
#include "fcfg_server_global.h"
#include "fcfg_server_dao.h"

int fcfg_server_dao_init(MYSQL *mysql)

{
    mysql_init(mysql);

    if (mysql_real_connect(mysql,
            g_server_global_vars.db_config.host,
            g_server_global_vars.db_config.user,
            g_server_global_vars.db_config.password,
            g_server_global_vars.db_config.database,
            g_server_global_vars.db_config.port,
            NULL, 0) == NULL)
    {
    }

    return 0;
}

void fcfg_server_dao_destroy(MYSQL *mysql)
{
}


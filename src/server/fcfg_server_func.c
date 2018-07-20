
#include <sys/stat.h>
#include "fastcommon/ini_file_reader.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "sf/sf_global.h"
#include "sf/sf_service.h"
#include "common/fcfg_types.h"
#include "fcfg_server_global.h"
#include "fcfg_server_func.h"

int fcfg_server_load_config(const char *filename)
{
    IniContext ini_context;
    char server_config_str[256];
    int result;

    memset(&ini_context, 0, sizeof(IniContext));
    if ((result=iniLoadFromFile(filename, &ini_context)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "load conf file \"%s\" fail, ret code: %d",
                __LINE__, filename, result);
        return result;
    }

    if ((result=sf_load_config("fcfg_serverd", filename, &ini_context,
                    FCFG_SERVER_DEFAULT_INNER_PORT,
                    FCFG_SERVER_DEFAULT_OUTER_PORT)) != 0)
    {
        return result;
    }

    iniFreeContext(&ini_context);

    /*
    sprintf(server_config_str, "tmp_base_path=%s, model_data_path=%s",
            tmp_base_path, g_server_global_vars.model_data_path);
            */
    *server_config_str = '\0';
    sf_log_config_ex(server_config_str);
    return 0;
}

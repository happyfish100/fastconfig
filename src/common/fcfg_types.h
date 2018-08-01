#ifndef _FCFG_TYPES_H
#define _FCFG_TYPES_H

#include <time.h>
#include "fastcommon/common_define.h"

#define FCFG_ERROR_INFO_SIZE             256

#define FCFG_CONFIG_STATUS_NORMAL        0
#define FCFG_CONFIG_STATUS_DELETED       1

#define FCFG_CONFIG_MAX_ENV_LEN     64
#define FCFG_CONFIG_MAX_NAME_LEN    64
#define FCFG_CONFIG_MAX_VALUE_LEN   (64 * 1024)

#define FCFG_CONFIG_ENV_SIZE     (FCFG_CONFIG_MAX_ENV_LEN + 1)
#define FCFG_CONFIG_NAME_SIZE    (FCFG_CONFIG_MAX_NAME_LEN + 1)
#define FCFG_CONFIG_VALUE_SIZE   (FCFG_CONFIG_MAX_VALUE_LEN + 1)

#define FCFG_NETWORK_TIMEOUT_DEFAULT    30
#define FCFG_CONNECT_TIMEOUT_DEFAULT    30

#define FCFG_CONFIG_SERVER_COUNT_MAX    10

typedef struct {
    unsigned char cmd;  //response command
    int body_len;       //response body length
} FCFGRequestInfo;

typedef struct {
    struct {
        char message[FCFG_ERROR_INFO_SIZE];
        int length;
    } error;
    int status;
    int body_len;    //response body length
    bool response_done;
    unsigned char cmd;   //response command
} FCFGResponseInfo;

typedef struct fcfg_config_entry {
    string_t name;
    string_t value;
    int64_t version;
    short status;
    time_t create_time;  //unix timestamp
    time_t update_time;  //unix timestamp
} FCFGConfigEntry;

typedef struct {
    FCFGConfigEntry *rows;
    int alloc;
    int count;
    int64_t version;
} FCFGConfigArray;

typedef struct fcfg_env_entry {
    string_t env;
    time_t create_time;  //unix timestamp
    time_t update_time;  //unix timestamp
} FCFGEnvEntry;

typedef struct {
    FCFGEnvEntry *rows;
    int count;
} FCFGEnvArray;

#endif

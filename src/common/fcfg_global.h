/*
 * Copyright (c) 2020 YuQing <384681@qq.com>
 *
 * This program is free software: you can use, redistribute, and/or modify
 * it under the terms of the GNU Affero General Public License, version 3
 * or later ("AGPL"), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */


#ifndef _FCFG_GLOBAL_H
#define _FCFG_GLOBAL_H

#include "fcfg_types.h"

typedef struct fcfg_global_vars {
    Version version;
} FCFGGlobalVars;

#ifdef __cplusplus
extern "C" {
#endif

    extern FCFGGlobalVars g_fcfg_global_vars;

#ifdef __cplusplus
}
#endif

#endif

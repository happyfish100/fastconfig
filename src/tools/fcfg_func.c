#include <stdio.h>
#include "fcfg_admin.h"

void fcfg_print_env_array (FCFGEnvArray *array)
{
    int i;

    fprintf(stderr,"Env count:%d\n", array->count);
    for (i = 0; i < array->count; i++) {
        fprintf(stderr, "Env %d: %s\n", i, (array->rows+i)->env.str);
    }
}

void fcfg_print_config_array (FCFGConfigArray *array)
{
    int i;

    fprintf(stderr, "Config count:%d\n", array->count);
    for (i = 0; i < array->count; i++) {
        fprintf(stderr, "%d: "
                "%s => %s\n",
                i,
                (array->rows + i)->name.str,
                (array->rows + i)->value.str);
    }
}

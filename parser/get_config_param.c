#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ini.h"
#include "get_config_param.h"
static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
    configuration* pconfig = (configuration*)user;

    #define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
    if (MATCH("timings", "max_life")) {
        pconfig->max_life = *value;
    } else if (MATCH("timings", "max_renewable_life")) {
        pconfig->max_renewable_life = *value;
    } else if (MATCH("timings", "timeout")) {
        pconfig->timeout = atoi(value);
    } else if (MATCH("timings", "retries")) {
          pconfig->retries = atoi(value);
    } else if (MATCH("timings", "ticket_lifetime")) {
          pconfig->ticket_lifetime = atoi(value);
    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}

int get_config_param(configuration *conf)
{
    if (ini_parse("config.ini", handler, conf) < 0) {
        printf("Can't load 'test.ini'\n");
        return 1;
    }
    printf("Config loaded from 'test.ini': max_life=%d, max_renewable_life=%d, timeout=%d  retries=%d    ticket_lifetime=%d\n",
        conf->max_life, conf->max_renewable_life, conf->timeout,conf->retries,conf->ticket_lifetime);
    return 0;
}

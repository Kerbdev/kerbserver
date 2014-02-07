#ifndef GET_CONF_H_
#define GET_CONG_H_
typedef struct
{
    const char *max_life;
    const char *max_renewable_life;
    int timeout;
    int retries;
    const char *ticket_lifetime;
} configuration;
int get_config_param(configuration *config);



#endif

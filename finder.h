#ifndef __FINDER_H__
#define __FINDER_H__

#include <iot/mongoose.h>


struct finder_option {
    const char *service;
    const char *broadcast_port;  //udp 广播端口
    const char *callback_lua;
    const char *payload;
    const char *key;
    int count;
    int debug_level;
};

struct finder_config {
    struct finder_option *opts;
};

struct finder_private {
    struct finder_config cfg;
    struct mg_mgr mgr;

    char finder_id[21]; //id len 20 + 0
};

int finder_main(void *user_options);

#endif
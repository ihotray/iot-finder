#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <net/if.h>
#include <lualib.h>
#include <lauxlib.h>
#include <iot/mongoose.h>
#include <iot/cJSON.h>
#include "finder.h"

#define FD(c_) ((MG_SOCKET_TYPE) (size_t) (c_)->fd)

static void udp_ev_connect_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (c->fn_data) {
        MG_ERROR(("bad logic error"));
        exit(EXIT_FAILURE);
    }

    c->fn_data = calloc(1, sizeof(uint64_t));
    if (!c->fn_data) {
        MG_ERROR(("OOM"));
        exit(EXIT_FAILURE);
    }

    *(uint64_t*)(c->fn_data) = mg_millis();
}

static void payload_cb(void *handle, cJSON *req) {
    struct finder_private *priv = (struct finder_private *)handle;
    const char* request = cJSON_Print(req);
    const char *response = NULL;
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);

    if ( luaL_dofile(L, priv->cfg.opts->callback_lua) ) {
        MG_ERROR(("lua dofile failed"));
        goto done;
    }

    lua_getfield(L, -1, "on_message");
    if (!lua_isfunction(L, -1)) {
        MG_ERROR(("method on_message is not a function"));
        goto done;
    }

    lua_pushstring(L, request);

    if (lua_pcall(L, 1, 1, 0)) {//one param, one return values, zero error func
        MG_ERROR(("callback failed"));
        goto done;
    }

    response = lua_tostring(L, -1);
    if (!response) {
        MG_ERROR(("lua call no response"));
        goto done;
    }

    MG_INFO(("response: %s", response));

done:
    if (request)
        cJSON_free((void*)request);

    if (L)
        lua_close(L);
}

static void udp_ev_read_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (c->recv.len > 0) {
        MG_INFO(("udp_ev_read_cb: %.*s",  c->recv.len, (char *)c->recv.buf));
        struct finder_private *priv = (struct finder_private *)c->mgr->userdata;
        cJSON *root = cJSON_ParseWithLength((char *)c->recv.buf, c->recv.len);
        cJSON *service = cJSON_GetObjectItem(root, "service");
        cJSON *payload = cJSON_GetObjectItem(root, "payload");
        if ( cJSON_IsString(service) && mg_casecmp(service->valuestring, priv->cfg.opts->service) == 0 \
            && cJSON_IsString(payload)) {
            payload_cb(priv, payload);
        } else {
            MG_ERROR(("service name not match or no payload found"));
        }
        cJSON_Delete(root);
    }
    c->recv.len = 0;
    c->is_draining = 1; //close connection
}

static void udp_ev_poll_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (!c->fn_data) {
        return;
    }
    if (mg_millis() - *(uint64_t*)(c->fn_data) > 15000) { //15s timeout
        //MG_INFO(("connection %llu timeout", c->id));
        c->is_draining = 1; //close connection
    }
}

static void udp_ev_close_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (!c->fn_data) {
        return;
    }
    free(c->fn_data);
    c->fn_data = NULL;
}

// Event handler for the listening connection.
static void udp_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    switch (ev) {
        case MG_EV_CONNECT:
            udp_ev_connect_cb(c, ev, ev_data, fn_data);
            break;
        case MG_EV_READ:
            udp_ev_read_cb(c, ev, ev_data, fn_data);
            break;
        case MG_EV_POLL:
            udp_ev_poll_cb(c, ev, ev_data, fn_data);
            break;
        case MG_EV_CLOSE:
            udp_ev_close_cb(c, ev, ev_data, fn_data);
            break;
    }
}

static void do_broadcast(void *arg, void *addr) {
    struct mg_mgr *mgr = (struct mg_mgr *)arg;
    struct finder_private *priv = (struct finder_private *)mgr->userdata;
    struct mg_connection *c;
    cJSON *root = NULL;
    char *printed = NULL;
    int flag = 1;

    char * broadcast_addr = mg_mprintf("udp://%s:%s", addr, priv->cfg.opts->broadcast_port);
    c = mg_connect(mgr, broadcast_addr, udp_cb, NULL);
    if (!c) {
        MG_ERROR(("cannot connect to %s", broadcast_addr));
        goto done;
    }
    setsockopt(FD(c), SOL_SOCKET, SO_BROADCAST, &flag, sizeof(flag));

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "service", priv->cfg.opts->service);
    cJSON_AddStringToObject(root, "address", addr);
    cJSON_AddStringToObject(root, "payload", priv->cfg.opts->payload);
    printed = cJSON_Print(root);
    mg_send(c, printed, strlen(printed));

done:
    free(broadcast_addr);
    if (printed)
        cJSON_free((void*)printed);
    if (root)
        cJSON_Delete(root);
}

static void broadcast(void *arg) {
    struct ifaddrs* ifaddr = NULL;
    struct ifaddrs* ifa = NULL;

    if (getifaddrs(&ifaddr) < 0)
        MG_ERROR(("unable to get interface addresses\n"));

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;
        if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_BROADCAST))
            continue;
        if ((ifa->ifa_flags & IFF_LOOPBACK) || (ifa->ifa_flags & IFF_POINTOPOINT))
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* saddr = (struct sockaddr_in*)ifa->ifa_ifu.ifu_broadaddr;
            char broadcast_addr[32] = {0};
            inet_ntop(AF_INET, &(saddr->sin_addr), broadcast_addr, sizeof(broadcast_addr));
            MG_INFO(("%16s's broadcast addr: %s", ifa->ifa_name, broadcast_addr)); 
            do_broadcast(arg, broadcast_addr);
        }
    }

    if (ifaddr)
        freeifaddrs(ifaddr);
}

static int s_signo = 0;
static int s_sig_broadcast = 1;

void timer_finder_fn(void *arg) {
    if (s_sig_broadcast) {
        MG_INFO(("broadcasting..."));
        broadcast(arg);
        s_sig_broadcast = 0;
    }
}

static void signal_handler(int signo) {
    switch (signo) {
    case SIGUSR1:
        s_sig_broadcast = 1;
        break;
    default:
        s_signo = signo;
        break;
    }
}

int finder_init(void **priv, void *opts) {

    struct finder_private *p;
    int timer_opts = MG_TIMER_REPEAT | MG_TIMER_RUN_NOW;

    signal(SIGINT, signal_handler);   // Setup signal handlers - exist event
    signal(SIGTERM, signal_handler);  // manager loop on SIGINT and SIGTERM
    signal(SIGUSR1, signal_handler);

    *priv = NULL;
    p = calloc(1, sizeof(struct finder_private));
    if (!p)
        return -1;

    p->cfg.opts = opts;
    mg_log_set(p->cfg.opts->debug_level);

    mg_mgr_init(&p->mgr);

    p->mgr.userdata = p;

    mg_timer_add(&p->mgr, 1000, timer_opts, timer_finder_fn, &p->mgr);  //1s, repeat broadcast if need

    *priv = p;

    return 0;

}


void finder_run(void *handle) {
    struct finder_private *priv = (struct finder_private *)handle;
    while (s_signo == 0) mg_mgr_poll(&priv->mgr, 1000);  // Event loop, 1000ms timeout
}

void finder_exit(void *handle) {
    struct finder_private *priv = (struct finder_private *)handle;
    mg_mgr_free(&priv->mgr);
    free(handle);
}

int finder_main(void *user_options) {

    struct finder_option *opts = (struct finder_option *)user_options;
    void *finder_handle;
    int ret;

    ret = finder_init(&finder_handle, opts);
    if (ret)
        exit(EXIT_FAILURE);

    finder_run(finder_handle);

    finder_exit(finder_handle);

    return 0;

}
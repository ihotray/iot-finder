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

static void udp_payload_read_cb(struct mg_connection *c, cJSON *request, cJSON *nonce) {
    struct finder_private *priv = (struct finder_private *)c->mgr->userdata;
    const char *ret = NULL;
    const char *response = NULL;
    cJSON *root = NULL;
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

    lua_pushstring(L, request->valuestring);

    if (lua_pcall(L, 1, 1, 0)) {//one param, one return values, zero error func
        MG_ERROR(("callback failed"));
        goto done;
    }

    ret = lua_tostring(L, -1);
    if (!ret) {
        MG_ERROR(("lua call no ret"));
        goto done;
    }

    MG_DEBUG(("ret: %s", ret));

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "service", priv->cfg.opts->service);
    cJSON_AddStringToObject(root, "finder", priv->cfg.finder_id);
    cJSON_AddStringToObject(root, "payload", ret);
    cJSON_AddNumberToObject(root, "nonce", nonce->valueint);

    //add sign, sha1(service + finder + payload + nonce + key)
    unsigned char digest[20] = {0};
    char sign_str[41] = {0};
    char *data = mg_mprintf("%s%s%s%d%s", priv->cfg.opts->service, priv->cfg.finder_id, ret, nonce->valueint, priv->cfg.opts->key);
    mg_sha1_ctx ctx;
    mg_sha1_init(&ctx);
    mg_sha1_update(&ctx, (const unsigned char *)data, strlen(data));
    mg_sha1_final(digest, &ctx);
    free(data);

    mg_hex(digest, sizeof(digest), sign_str);
    cJSON_AddStringToObject(root, "sign", sign_str);

    char remote[16] = {0};
    mg_snprintf(remote, sizeof(remote), "%M", mg_print_ip, &c->rem);
    response = cJSON_Print(root);

    MG_INFO(("response: %s -> %s", response, remote));

    mg_send(c, response, strlen(response));

done:
    if (response)
        cJSON_free((void*)response);
    if (root)
        cJSON_Delete(root);
    if (L)
        lua_close(L);
}

static void udp_ev_read_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (c->fn_data)
        *(uint64_t*)(c->fn_data) = mg_millis();

    if (c->recv.len > 0) {
        char remote[16] = {0};
        mg_snprintf(remote, sizeof(remote), "%M", mg_print_ip, &c->rem);

        MG_INFO(("udp_ev_read_cb: %.*s <- %s", c->recv.len, (char *)c->recv.buf, remote));
        struct finder_private *priv = (struct finder_private *)c->mgr->userdata;
        cJSON *root = cJSON_ParseWithLength((char *)c->recv.buf, c->recv.len);
        cJSON *service = cJSON_GetObjectItem(root, "service");
        cJSON *finder = cJSON_GetObjectItem(root, "finder");
        cJSON *payload = cJSON_GetObjectItem(root, "payload");
        cJSON *nonce = cJSON_GetObjectItem(root, "nonce");
        cJSON *sign = cJSON_GetObjectItem(root, "sign");
        //check service name matched and drop the message from itself
        if ( cJSON_IsString(service) && mg_casecmp(cJSON_GetStringValue(service), priv->cfg.opts->service) == 0 \
            && cJSON_IsString(finder) && mg_casecmp(cJSON_GetStringValue(finder), priv->cfg.finder_id) \
            && cJSON_IsString(payload) && cJSON_IsNumber(nonce) && cJSON_IsString(sign) \
            && nonce->valueint + 60 >  mg_millis() / 1000 ) { //只处理60s内的回复，防止重放攻击

            //check sign, sha1(service + finder + payload + nonce + key)
            unsigned char digest[20] = {0};
            char sign_str[41] = {0};
            char *data = mg_mprintf("%s%s%s%d%s", priv->cfg.opts->service, cJSON_GetStringValue(finder), cJSON_GetStringValue(payload), \
                nonce->valueint, priv->cfg.opts->key);
            //MG_DEBUG(("data: %s", data));
            mg_sha1_ctx ctx;
            mg_sha1_init(&ctx);
            mg_sha1_update(&ctx, (const unsigned char *)data, strlen(data));
            mg_sha1_final(digest, &ctx);
            free(data);

            mg_hex(digest, sizeof(digest), sign_str);

            if ( mg_casecmp(cJSON_GetStringValue(sign), sign_str) == 0 ) { //sign matched
                udp_payload_read_cb(c, payload, nonce);
            } else {
                MG_ERROR(("sign not matched"));
            }

        } else {
            MG_ERROR(("unexpected message"));
        }
        cJSON_Delete(root);
    }
    c->recv.len = 0;

}

static void udp_ev_poll_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (c->is_listening)
        return;

    if (!c->fn_data)
        return;

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

static cJSON* load_message(void *handle, const char *message) {
    struct finder_private *priv = (struct finder_private *)handle;
    cJSON *payload = NULL;
    const char *ret = NULL;
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);

    if ( luaL_dofile(L, priv->cfg.opts->callback_lua) ) {
        MG_ERROR(("lua dofile failed"));
        goto done;
    }

    lua_getfield(L, -1, "load_message");
    if (!lua_isfunction(L, -1)) {
        MG_ERROR(("method load_message is not a function"));
        goto done;
    }

    if (lua_pcall(L, 0, 1, 0)) {//0 param, one return values, zero error func
        MG_ERROR(("callback failed"));
        goto done;
    }

    ret = lua_tostring(L, -1);
    if (!ret) {
        MG_ERROR(("lua call no ret"));
        goto done;
    }

    MG_INFO(("ret: %s", ret));

done:
    if (ret) {
        payload = cJSON_CreateString(ret);
    } else if (message) {
        payload = cJSON_CreateString(message);
    }
    if (L)
        lua_close(L);

    return payload;
}

static void do_broadcast(void *arg, void *address) {
    struct mg_mgr *mgr = (struct mg_mgr *)arg;
    struct finder_private *priv = (struct finder_private *)mgr->userdata;
    struct mg_connection *c;
    cJSON *root = NULL, *payload = NULL;
    char *printed = NULL;
    int flag = 1;

    char *broadcast_address = mg_mprintf("udp://%s:%s", address, priv->cfg.opts->broadcast_port);
    c = mg_connect(mgr, broadcast_address, udp_cb, NULL);
    if (!c) {
        MG_ERROR(("cannot connect to %s", broadcast_address));
        goto done;
    }
    setsockopt(FD(c), SOL_SOCKET, SO_BROADCAST, &flag, sizeof(flag));

    uint64_t nonce = mg_millis()/1000;

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "service", priv->cfg.opts->service);
    cJSON_AddStringToObject(root, "finder", priv->cfg.finder_id);

    payload = load_message(priv, priv->cfg.opts->payload); //maybe change default payload by lua script
    if (!payload) //no payload, skip this broadcast
        goto done;

    //add address to payload
    cJSON *new_payload = cJSON_Parse(cJSON_GetStringValue(payload));
    if (new_payload) {
        cJSON_AddStringToObject(new_payload, "address", address);
        char *new_payload_str = cJSON_PrintUnformatted(new_payload);
        cJSON_SetValuestring(payload, new_payload_str);
        cJSON_free((void*)new_payload_str);
        cJSON_Delete(new_payload);
    }

    cJSON_AddItemToObject(root, "payload", payload);

    cJSON_AddNumberToObject(root, "nonce", nonce);

    //add sign, sha1(service + finder_id + payload + nonce + key)
    unsigned char digest[20] = {0};
    char sign_str[41] = {0};
    char *data = mg_mprintf("%s%s%s%d%s", priv->cfg.opts->service, priv->cfg.finder_id, cJSON_GetStringValue(payload), \
        nonce, priv->cfg.opts->key);
    //MG_DEBUG(("data: %s", data));
    mg_sha1_ctx ctx;
    mg_sha1_init(&ctx);
    mg_sha1_update(&ctx, (const unsigned char *)data, strlen(data));
    mg_sha1_final(digest, &ctx);
    free(data);

    mg_hex(digest, sizeof(digest), sign_str);
    cJSON_AddStringToObject(root, "sign", sign_str);

    printed = cJSON_Print(root);
    MG_INFO(("do_broadcast: %s -> %s", printed, broadcast_address));
    mg_send(c, printed, strlen(printed));

done:
    free(broadcast_address);
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
            char broadcast_address[32] = {0};
            inet_ntop(AF_INET, &(saddr->sin_addr), broadcast_address, sizeof(broadcast_address));
            MG_INFO(("%16s's broadcast address: %s", ifa->ifa_name, broadcast_address));
            do_broadcast(arg, broadcast_address);
        }
    }

    if (ifaddr)
        freeifaddrs(ifaddr);
}

static int s_signo = 0;
static int s_sig_broadcast = 1;
static int s_broadcast_times = 0;
static uint64_t s_next_broadcast_time = 0;

static void on_finish_cb(void *arg) {
    struct mg_mgr *mgr = (struct mg_mgr *)arg;
    struct finder_private *priv = (struct finder_private *)mgr->userdata;
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);

    if ( luaL_dofile(L, priv->cfg.opts->callback_lua) ) {
        MG_ERROR(("lua dofile failed"));
        goto done;
    }

    lua_getfield(L, -1, "on_finish");
    if (!lua_isfunction(L, -1)) {
        MG_ERROR(("method on_finish is not a function"));
        goto done;
    }

    if (lua_pcall(L, 0, 0, 0)) {//0 param, 0 return values, zero error func
        MG_ERROR(("callback failed"));
        goto done;
    }

done:
    if (L)
        lua_close(L);
}

void timer_finder_fn(void *arg) {
    struct mg_mgr *mgr = (struct mg_mgr *)arg;
    struct finder_private *priv = (struct finder_private *)mgr->userdata;
    if (s_sig_broadcast) {
        uint64_t now = mg_millis();
        if (now < s_next_broadcast_time) //not time yet
            return;

        MG_INFO(("broadcasting..."));
        broadcast(arg);

        s_next_broadcast_time = now + (priv->cfg.opts->time*1000)/priv->cfg.opts->count;

        if (++s_broadcast_times >= priv->cfg.opts->count) {//finished this time
            s_sig_broadcast = 0;
            on_finish_cb(arg);  //call lua script on_finish
        }
    }
}

static void signal_handler(int signo) {
    switch (signo) {
    case SIGUSR1:
        s_sig_broadcast = 1;
        s_broadcast_times = 0;
        s_next_broadcast_time = mg_millis();
        break;
    case SIGUSR2:
        s_sig_broadcast = 0;
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
    signal(SIGUSR2, signal_handler);

    *priv = NULL;
    p = calloc(1, sizeof(struct finder_private));
    if (!p)
        return -1;

    //生成finder id
    char rnd[10];
    mg_random(rnd, sizeof(rnd));
    mg_hex(rnd, sizeof(rnd), p->cfg.finder_id);

    MG_INFO(("finder id: %s", p->cfg.finder_id));

    p->cfg.opts = opts;
    mg_log_set(p->cfg.opts->debug_level);

    mg_mgr_init(&p->mgr);

    p->mgr.userdata = p;

    //receive broadcast's packet as controller
    char *listen_address = mg_mprintf("udp://:%s", p->cfg.opts->broadcast_port);
    struct mg_connection *c = mg_listen(&p->mgr, listen_address, udp_cb, NULL);
    free(listen_address);
    if (!c) {
        MG_ERROR(("Cannot listen on %s. Use udp://ADDR:PORT or :PORT", p->cfg.opts->broadcast_port));
        goto out_err;
    }

    //send broadcast packet as agent
    mg_timer_add(&p->mgr, 1000, timer_opts, timer_finder_fn, &p->mgr);  //1s, repeat broadcast if need

    *priv = p;

    return 0;

out_err:
    free(p);
    return -1;
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
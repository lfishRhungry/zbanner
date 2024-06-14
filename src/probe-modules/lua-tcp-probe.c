#include "probe-modules.h"

#include "../version.h"
#include "../xconf.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../util-misc/cross.h"

#include "../stub/stub-lua.h"

#define LUA_PROBE_NAME    "LuaTcpProbe"
#define LUA_PROBE_TYPE    "tcp"
#define LUA_PROBE_EG      "tcp-example.lua"

#define LUA_PROBE_VAR_PROBENAME             "ProbeName"
#define LUA_PROBE_VAR_PROBETYPE             "ProbeType"
#define LUA_PROBE_VAR_MULTIMODE             "MultiMode"
#define LUA_PROBE_VAR_MULTINUM              "MultiNum"
#define LUA_PROBE_VAR_PROBEDESC             "ProbeDesc"

#define LUA_PROBE_MULTI_NULL                "null"
#define LUA_PROBE_MULTI_DIRECT              "direct"
#define LUA_PROBE_MULTI_IFOPEN              "if_open"
#define LUA_PROBE_MULTI_AFTERHANDLE         "after_handle"
#define LUA_PROBE_MULTI_DYNAMICNEXT         "dynamic_next"

#define LUA_PROBE_FUNC_MAKE_PAYLOAD         "Make_payload"
#define LUA_PROBE_FUNC_GET_PAYLOAD_LEN      "Get_payload_length"
#define LUA_PROBE_FUNC_HANDLE_RESPONSE      "Handle_response"
#define LUA_PROBE_FUNC_HANDLE_TIMEOUT       "Handle_timeout"

/*for internal x-ref*/
extern struct ProbeModule LuaTcpProbe;

struct LuaTcpConf {
    char *script;
    /**
     * Until now, I have no better way to solve multi-thread problem across Lua
     * and Xtate. So it's good to design a good workflow for Lua probe.
     * 
     * For tcp type probe, there're 3 funcs correspond to 3 essential threads at
     * least:
     * Tx: make_payload
     * Rx: get_payload_length
     * Rx(handler): handler_response
     * 
     * So I brutely limit the multi-thread of Xtate and create 3 Lua VM for those
     * callback funcs. It's effective and causes that 3 funcs should be thread-
     * seperate.
     * 
     * Well, we can't ask lua probe do everything like a real probe module, right?
     * 
     * TODO: Maybe one thread for one Lua VM to support full multi-thread of Xtate.
    */
    lua_State *Ltx;            /*for make_payload*/
    lua_State *Lrx;            /*for get_payload_length and handle_timeout*/
    lua_State *Lhx;            /*for handle_response*/
};

static struct LuaTcpConf luatcp_conf = {0};

static enum ConfigRes SET_script(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (luatcp_conf.script)
        free(luatcp_conf.script);

    luatcp_conf.script = STRDUP(value);

    return Conf_OK;
}

static struct ConfigParam luatcp_parameters[] = {
    {
        "script",
        SET_script,
        Type_NONE,
        {0},
        "Specifies which lua script we'll load to as probe."
    },

    {0}
};

/**
 * Simply check funcs in Ltx
*/
static bool check_func_exist(const char *func)
{
    lua_getglobal(luatcp_conf.Ltx, func);
    if (lua_isfunction(luatcp_conf.Ltx, -1)==0) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": no `%s` func in script %s.\n",
            func, luatcp_conf.script);
        return false;
    }
    lua_pop(luatcp_conf.Ltx, 1);
    return true;
}

static bool sync_probe_config()
{
    /*probe name*/
    lua_getglobal(luatcp_conf.Ltx, LUA_PROBE_VAR_PROBENAME);
    if (lua_isstring(luatcp_conf.Ltx, -1)==0) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": no `"LUA_PROBE_VAR_PROBENAME"` setting in script %s.\n",
            luatcp_conf.script);
        return false;
    }
    LOG(LEVEL_INFO, "["LUA_PROBE_NAME"] "LUA_PROBE_VAR_PROBENAME": %s.\n", lua_tostring(luatcp_conf.Ltx, -1));
    lua_pop(luatcp_conf.Ltx, 1);

    /*probe type*/
    lua_getglobal(luatcp_conf.Ltx, LUA_PROBE_VAR_PROBETYPE);
    if (lua_isstring(luatcp_conf.Ltx, -1)==0) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": no `"LUA_PROBE_VAR_PROBETYPE"` setting in script %s.\n",
            luatcp_conf.script);
        return false;
    }
    if (strcmp(lua_tostring(luatcp_conf.Ltx, -1), LUA_PROBE_TYPE)!=0) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": need a "LUA_PROBE_TYPE" `"LUA_PROBE_VAR_PROBETYPE"` instead of %s type in %s.\n",
            lua_tostring(luatcp_conf.Ltx, -1), luatcp_conf.script);
        return false;
    }
    lua_pop(luatcp_conf.Ltx, 1);

    /*multi mode*/
    enum MultiMode *mode = (enum MultiMode *)&LuaTcpProbe.multi_mode;
    lua_getglobal(luatcp_conf.Ltx, LUA_PROBE_VAR_MULTIMODE);
    if (lua_isstring(luatcp_conf.Ltx, -1)==0) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": no `"LUA_PROBE_VAR_MULTIMODE"` setting in script %s.\n",
            luatcp_conf.script);
        return false;
    }
    if (strcmp(lua_tostring(luatcp_conf.Ltx, -1), LUA_PROBE_MULTI_NULL)==0) {
    } else if (strcmp(lua_tostring(luatcp_conf.Ltx, -1), LUA_PROBE_MULTI_DIRECT)==0) {
        *mode = Multi_Direct;
    } else if (strcmp(lua_tostring(luatcp_conf.Ltx, -1), LUA_PROBE_MULTI_IFOPEN)==0) {
        *mode = Multi_IfOpen;
    } else if (strcmp(lua_tostring(luatcp_conf.Ltx, -1), LUA_PROBE_MULTI_AFTERHANDLE)==0) {
        *mode = Multi_AfterHandle;
    } else if (strcmp(lua_tostring(luatcp_conf.Ltx, -1), LUA_PROBE_MULTI_DYNAMICNEXT)==0) {
        *mode = Multi_DynamicNext;
    } else {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": invalid `"LUA_PROBE_VAR_MULTIMODE"` setting in script %s.\n",
            luatcp_conf.script);
        return false;
    }
    lua_pop(luatcp_conf.Ltx, 1);

    /*multi num*/
    unsigned *num = (unsigned *)&LuaTcpProbe.multi_num;
    lua_getglobal(luatcp_conf.Ltx, LUA_PROBE_VAR_MULTINUM);
    if (lua_isinteger(luatcp_conf.Ltx, -1)==0) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": no `"LUA_PROBE_VAR_MULTINUM"` setting in script %s.\n",
            luatcp_conf.script);
        return false;
    }
    if (lua_tointeger(luatcp_conf.Ltx, -1) > 1) {
        *num = lua_tointeger(luatcp_conf.Ltx, -1);
    } else if (lua_tointeger(luatcp_conf.Ltx, -1) < 0) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": invalid `"LUA_PROBE_VAR_MULTINUM"` setting in script %s.\n",
            luatcp_conf.script);
        return false;
    }
    lua_pop(luatcp_conf.Ltx, 1);

    /*probe desc*/
    lua_getglobal(luatcp_conf.Ltx, LUA_PROBE_VAR_PROBEDESC);
    if (lua_isstring(luatcp_conf.Ltx, -1)==0) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": no `"LUA_PROBE_VAR_PROBEDESC"` setting in script %s.\n",
            luatcp_conf.script);
        return false;
    }
    lua_pop(luatcp_conf.Ltx, 1);

    return true;
}

static bool
luatcp_global_init(const struct Xconf *xconf)
{
    if (!luatcp_conf.script) {
        LOG(LEVEL_ERROR, "[-] "LUA_PROBE_NAME": must specify a lua script as probe by `--script`.\n");
        return false;
    }

    if (xconf->tx_thread_count!=1 || xconf->rx_handler_count!=1) {
        LOG(LEVEL_ERROR, "[-] "LUA_PROBE_NAME" doesn't support multi-tx-threads or multi-handle-threads now.\n");
        return false;
    }

    /* Dynamically link the library*/
    if (!stublua_init()) {
        LOG(LEVEL_ERROR, "[-]Failed to init lua library dynamicly.\n");
        LOG(LEVEL_ERROR, "    HINT: make sure lua library 5.3/5.4 was installed.\n");
        return false;
    }

    int x;

    /* Create Lua VM */
    luatcp_conf.Ltx = luaL_newstate();
    luatcp_conf.Lrx = luaL_newstate();
    luatcp_conf.Lhx = luaL_newstate();
    luaL_openlibs(luatcp_conf.Ltx);
    luaL_openlibs(luatcp_conf.Lrx);
    luaL_openlibs(luatcp_conf.Lhx);

    /* Get lua version*/
    lua_getglobal(luatcp_conf.Ltx, "_VERSION");
    const char *version = lua_tostring(luatcp_conf.Ltx, -1);
    LOG(LEVEL_HINT, "[-] Loaded lua library in %s\n", version);
    lua_pop(luatcp_conf.Ltx, 1);

    /* Load the script. This will verify the syntax.*/
    x = luaL_loadfile(luatcp_conf.Ltx, luatcp_conf.script);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "FAIL: %s error loading: %s: %s for Tx\n", "SCRIPTING:",
            luatcp_conf.script, lua_tostring(luatcp_conf.Ltx, -1));
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        lua_close(luatcp_conf.Lhx);
        free(luatcp_conf.script);
        return false;
    }
    x = luaL_loadfile(luatcp_conf.Lrx, luatcp_conf.script);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "FAIL: %s error loading: %s: %s for Rx\n", "SCRIPTING:",
            luatcp_conf.script, lua_tostring(luatcp_conf.Lrx, -1));
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        lua_close(luatcp_conf.Lhx);
        free(luatcp_conf.script);
        return false;
    }
    x = luaL_loadfile(luatcp_conf.Lhx, luatcp_conf.script);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "FAIL: %s error loading: %s: %s for Handler\n", "SCRIPTING:",
            luatcp_conf.script, lua_tostring(luatcp_conf.Lhx, -1));
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        lua_close(luatcp_conf.Lhx);
        free(luatcp_conf.script);
        return false;
    }

    /*
     * Lua: Start running the script and we can see global variables and funcs.
     * Just need to check for one VM because of same script.
     */
    LOG(LEVEL_WARNING, ""LUA_PROBE_NAME" running script: %s\n", luatcp_conf.script);
    x = lua_pcall(luatcp_conf.Ltx, 0, 0, 0);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": error running %s: %s for Tx\n",
            luatcp_conf.script, lua_tostring(luatcp_conf.Ltx, -1));
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        lua_close(luatcp_conf.Lhx);
        free(luatcp_conf.script);
        return false;
    }
    x = lua_pcall(luatcp_conf.Lrx, 0, 0, 0);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": error running %s: %s for Rx\n",
            luatcp_conf.script, lua_tostring(luatcp_conf.Lrx, -1));
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        lua_close(luatcp_conf.Lhx);
        free(luatcp_conf.script);
        return false;
    }
    x = lua_pcall(luatcp_conf.Lhx, 0, 0, 0);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": error running %s: %s for Handler\n",
            luatcp_conf.script, lua_tostring(luatcp_conf.Lhx, -1));
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        lua_close(luatcp_conf.Lhx);
        free(luatcp_conf.script);
        return false;
    }

    /**
     *Sync config
    */
    if (!sync_probe_config()) {
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        lua_close(luatcp_conf.Lhx);
        free(luatcp_conf.script);
        return false;
    }

    /**
     * Check tcp type callback funcs
    */
    if (!check_func_exist(LUA_PROBE_FUNC_MAKE_PAYLOAD)) {
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        lua_close(luatcp_conf.Lhx);
        free(luatcp_conf.script);
        return false;
    }
    if (!check_func_exist(LUA_PROBE_FUNC_GET_PAYLOAD_LEN)) {
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        lua_close(luatcp_conf.Lhx);
        free(luatcp_conf.script);
        return false;
    }
    if (!check_func_exist(LUA_PROBE_FUNC_HANDLE_RESPONSE)) {
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        lua_close(luatcp_conf.Lhx);
        free(luatcp_conf.script);
        return false;
    }
    if (!check_func_exist(LUA_PROBE_FUNC_HANDLE_TIMEOUT)) {
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        lua_close(luatcp_conf.Lhx);
        free(luatcp_conf.script);
        return false;
    }

    lua_settop(luatcp_conf.Ltx, 0);
    return true;
}

static size_t
luatcp_make_payload(
    struct ProbeTarget *target,
    unsigned char *payload_buf)
{
    const char *ret;
    size_t ret_len;

    lua_getglobal(luatcp_conf.Ltx, LUA_PROBE_FUNC_MAKE_PAYLOAD);
    lua_pushstring(luatcp_conf.Ltx, ipaddress_fmt(target->ip_them).string);
    lua_pushinteger(luatcp_conf.Ltx, target->port_them);
    lua_pushstring(luatcp_conf.Ltx, ipaddress_fmt(target->ip_me).string);
    lua_pushinteger(luatcp_conf.Ltx, target->port_me);
    lua_pushinteger(luatcp_conf.Ltx, target->index);

    if (lua_pcall(luatcp_conf.Ltx, 5, 1, 0) != LUA_OK) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_MAKE_PAYLOAD"` execute error in %s: %s\n",
            luatcp_conf.script, lua_tostring(luatcp_conf.Ltx, -1));
        lua_settop(luatcp_conf.Ltx, 0);
        return 0;
    }

    if (lua_isstring(luatcp_conf.Ltx, -1)==0) {
        LOG(LEVEL_ERROR, ""LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_MAKE_PAYLOAD"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Ltx, 0);
        return 0;
    }

    ret = lua_tolstring(luatcp_conf.Ltx, -1, &ret_len);
    memcpy(payload_buf, ret, ret_len);
    lua_settop(luatcp_conf.Ltx, 0);
    return ret_len;
}

static size_t
luatcp_get_payload_length(struct ProbeTarget *target)
{
    int ret_len;

    lua_getglobal(luatcp_conf.Lrx, LUA_PROBE_FUNC_GET_PAYLOAD_LEN);
    lua_pushstring(luatcp_conf.Lrx, ipaddress_fmt(target->ip_them).string);
    lua_pushinteger(luatcp_conf.Lrx, target->port_them);
    lua_pushstring(luatcp_conf.Lrx, ipaddress_fmt(target->ip_me).string);
    lua_pushinteger(luatcp_conf.Lrx, target->port_me);
    lua_pushinteger(luatcp_conf.Lrx, target->index);

    if (lua_pcall(luatcp_conf.Lrx, 5, 1, 0) != LUA_OK) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_GET_PAYLOAD_LEN"` execute error in %s: %s\n",
            luatcp_conf.script, lua_tostring(luatcp_conf.Lrx, -1));
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }

    if (lua_isinteger(luatcp_conf.Lrx, -1)==0) {
        LOG(LEVEL_ERROR, ""LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_GET_PAYLOAD_LEN"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }

    ret_len = lua_tointeger(luatcp_conf.Lrx, -1);
    lua_settop(luatcp_conf.Lrx, 0);

    return ret_len;
}

static unsigned
luatcp_handle_response(
    unsigned th_idx,
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    const char *lua_ret;
    size_t ret_len;
    unsigned ret = 0;

    lua_getglobal(luatcp_conf.Lhx, LUA_PROBE_FUNC_HANDLE_RESPONSE);
    lua_pushstring(luatcp_conf.Lhx, ipaddress_fmt(target->ip_them).string);
    lua_pushinteger(luatcp_conf.Lhx, target->port_them);
    lua_pushstring(luatcp_conf.Lhx, ipaddress_fmt(target->ip_me).string);
    lua_pushinteger(luatcp_conf.Lhx, target->port_me);
    lua_pushinteger(luatcp_conf.Lhx, target->index);
    lua_pushlstring(luatcp_conf.Lhx, (const char *)px, sizeof_px);

    if (lua_pcall(luatcp_conf.Lhx, 6, 5, 0) != LUA_OK) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_HANDLE_RESPONSE"` execute error in %s: %s\n",
            luatcp_conf.script, lua_tostring(luatcp_conf.Lhx, -1));
        lua_settop(luatcp_conf.Lhx, 0);
        return 0;
    }

    if (lua_isinteger(luatcp_conf.Lhx, -5)==0) {
        LOG(LEVEL_ERROR, ""LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_HANDLE_RESPONSE"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lhx, 0);
        return 0;
    }
    if (lua_tointeger(luatcp_conf.Lhx, -5)>0) {
        ret = lua_tointeger(luatcp_conf.Lhx, -5);
    } else if (lua_tointeger(luatcp_conf.Lhx, -5)<0){
        LOG(LEVEL_ERROR, ""LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_HANDLE_RESPONSE"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lhx, 0);
        return 0;
    }

    if (lua_isboolean(luatcp_conf.Lhx, -4)==0) {
        LOG(LEVEL_ERROR, ""LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_HANDLE_RESPONSE"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lhx, 0);
        return 0;
    }
    if (lua_toboolean(luatcp_conf.Lhx, -4)>0) {
        item->level = OP_SUCCESS;
    } else {
        item->level = OP_FAILURE;
    }

    if (lua_isstring(luatcp_conf.Lhx, -3)==0) {
        LOG(LEVEL_ERROR, ""LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_HANDLE_RESPONSE"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lhx, 0);
        return 0;
    }
    lua_ret = lua_tolstring(luatcp_conf.Lhx, -3, &ret_len);
    memcpy(item->classification, lua_ret, ret_len);

    if (lua_isstring(luatcp_conf.Lhx, -2)==0) {
        LOG(LEVEL_ERROR, ""LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_HANDLE_RESPONSE"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lhx, 0);
        return 0;
    }
    lua_ret = lua_tolstring(luatcp_conf.Lhx, -2, &ret_len);
    memcpy(item->reason, lua_ret, ret_len);

    if (lua_isstring(luatcp_conf.Lhx, -1)==0) {
        LOG(LEVEL_ERROR, ""LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_HANDLE_RESPONSE"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lhx, 0);
        return 0;
    }
    lua_ret = lua_tolstring(luatcp_conf.Lhx, -1, &ret_len);
    dach_append(&item->report, "lua report", lua_ret, ret_len);

    lua_settop(luatcp_conf.Lhx, 0);
    return ret;
}

static unsigned
luatcp_handle_timeout(
    struct ProbeTarget *target,
    struct OutputItem *item)
{
    const char *lua_ret;
    size_t ret_len;
    unsigned ret = 0;

    lua_getglobal(luatcp_conf.Lrx, LUA_PROBE_FUNC_HANDLE_TIMEOUT);
    lua_pushstring(luatcp_conf.Lrx, ipaddress_fmt(target->ip_them).string);
    lua_pushinteger(luatcp_conf.Lrx, target->port_them);
    lua_pushstring(luatcp_conf.Lrx, ipaddress_fmt(target->ip_me).string);
    lua_pushinteger(luatcp_conf.Lrx, target->port_me);
    lua_pushinteger(luatcp_conf.Lrx, target->index);

    if (lua_pcall(luatcp_conf.Lrx, 5, 5, 0) != LUA_OK) {
        LOG(LEVEL_ERROR, "[-]"LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_HANDLE_TIMEOUT"` execute error in %s: %s\n",
            luatcp_conf.script, lua_tostring(luatcp_conf.Lrx, -1));
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }

    if (lua_isinteger(luatcp_conf.Lrx, -5)==0) {
        LOG(LEVEL_ERROR, ""LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_HANDLE_TIMEOUT"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }
    if (lua_tointeger(luatcp_conf.Lrx, -5)>0) {
        ret = lua_tointeger(luatcp_conf.Lrx, -5);
    } else if (lua_tointeger(luatcp_conf.Lrx, -5)<0){
        LOG(LEVEL_ERROR, ""LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_HANDLE_TIMEOUT"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }

    if (lua_isboolean(luatcp_conf.Lrx, -4)==0) {
        LOG(LEVEL_ERROR, ""LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_HANDLE_TIMEOUT"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }
    if (lua_toboolean(luatcp_conf.Lrx, -4)>0) {
        item->level = OP_SUCCESS;
    } else {
        item->level = OP_FAILURE;
    }

    if (lua_isstring(luatcp_conf.Lrx, -3)==0) {
        LOG(LEVEL_ERROR, ""LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_HANDLE_TIMEOUT"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }
    lua_ret = lua_tolstring(luatcp_conf.Lrx, -3, &ret_len);
    memcpy(item->classification, lua_ret, ret_len);

    if (lua_isstring(luatcp_conf.Lrx, -2)==0) {
        LOG(LEVEL_ERROR, ""LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_HANDLE_TIMEOUT"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }
    lua_ret = lua_tolstring(luatcp_conf.Lrx, -2, &ret_len);
    memcpy(item->reason, lua_ret, ret_len);

    if (lua_isstring(luatcp_conf.Lrx, -1)==0) {
        LOG(LEVEL_ERROR, ""LUA_PROBE_NAME": func `"LUA_PROBE_FUNC_HANDLE_TIMEOUT"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }
    lua_ret = lua_tolstring(luatcp_conf.Lrx, -1, &ret_len);
    dach_append(&item->report, "lua report", lua_ret, ret_len);

    lua_settop(luatcp_conf.Lrx, 0);
    return ret;
}

void luatcp_close()
{
    if (luatcp_conf.Ltx) {
        lua_close(luatcp_conf.Ltx);
    }
    if (luatcp_conf.Lrx) {
        lua_close(luatcp_conf.Lrx);
    }
    if (luatcp_conf.Lhx) {
        lua_close(luatcp_conf.Lhx);
    }
    if (luatcp_conf.script)
        free(luatcp_conf.script);

}

struct ProbeModule LuaTcpProbe = {
    .name       = "lua-tcp",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .params     = luatcp_parameters,
    .desc =
        LUA_PROBE_NAME" let a specifies proper lua script as a "LUA_PROBE_TYPE" type probe. It "
        "will save a lot of time for us to write simple probes or test ideas. "
        "The example script("LUA_PROBE_EG") could be found at lua-probes dir."
        " In a nutshell, we should set some global variables as probe config "
        "include:\n"
        "`"LUA_PROBE_VAR_PROBENAME"`\n"
        "`"LUA_PROBE_VAR_PROBETYPE"`\n"
        "`"LUA_PROBE_VAR_MULTIMODE"`\n"
        "`"LUA_PROBE_VAR_MULTINUM"`\n"
        "`"LUA_PROBE_VAR_PROBEDESC"`\n"
        "And implement 3 global functions for calling back include:\n"
        "`"LUA_PROBE_FUNC_MAKE_PAYLOAD"`\n"
        "`"LUA_PROBE_FUNC_GET_PAYLOAD_LEN"`\n"
        "`"LUA_PROBE_FUNC_HANDLE_RESPONSE"`\n"
        "`"LUA_PROBE_FUNC_HANDLE_TIMEOUT"`\n"
        "NOTE: This is an experimental function and does not support more than "
        "one tx thread or rx-handle thread well. Even through, it is mandatory "
        "to implement functions thread-seperately. However, we had 3 essential"
        " threads at least and should be careful to thread-safe problems.",
    .init_cb                                 = &luatcp_global_init,
    .make_payload_cb                         = &luatcp_make_payload,
    .get_payload_length_cb                   = &luatcp_get_payload_length,
    .handle_response_cb                      = &luatcp_handle_response,
    .handle_timeout_cb                       = &luatcp_handle_timeout,
    .close_cb                                = &luatcp_close,
};
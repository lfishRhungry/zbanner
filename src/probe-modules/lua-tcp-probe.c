#include "probe-modules.h"

#include "../version.h"
#include "../xconf.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../util-misc/cross.h"

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#define LUA_PROBE_VAR_PROBENAME         "ProbeName"
#define LUA_PROBE_VAR_PROBETYPE         "ProbeType"
#define LUA_PROBE_VAR_MULTIMODE         "MultiMode"
#define LUA_PROBE_VAR_MULTINUM          "MultiNum"
#define LUA_PROBE_VAR_ProbeDesc         "ProbeDesc"

#define LUA_PROBE_FUNC_GLOBAL_INIT      "Global_init"
#define LUA_PROBE_FUNC_MAKE_PAYLOAD     "Make_payload"
#define LUA_PROBE_FUNC_GET_PAYLOAD_LEN  "Get_payload_length"
#define LUA_PROBE_FUNC_HANDLE_RESPONSE  "Handle_response"
#define LUA_PROBE_FUNC_CLOSE            "Close"

/*for internal x-ref*/
extern struct ProbeModule LuaTcpProbe;

struct LuaTcpConf {
    char *script;
    lua_State *Ltx; /*for funcs: init, make_payload and close*/
    lua_State *Lrx; /*for funcs: get_payload_length and handle_response*/
};

static struct LuaTcpConf luatcp_conf = {0};

static enum Config_Res SET_script(void *conf, const char *name, const char *value)
{
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (luatcp_conf.script)
        free(luatcp_conf.script);
    
    luatcp_conf.script = STRDUP(value);

    return CONF_OK;
}

static struct ConfigParam luatcp_parameters[] = {
    {
        "script",
        SET_script,
        F_NONE,
        {0},
        "Specifies which lua script we'll load to as probe."
    },

    {0}
};

static bool check_func_exist(const char *func)
{
    lua_getglobal(luatcp_conf.Ltx, func);
    if (lua_isfunction(luatcp_conf.Ltx, -1)==0) {
        LOG(LEVEL_ERROR, "[-]LuaTcpProbe: no `%s` func in script %s.\n",
            func, luatcp_conf.script);
        return false;
    }
    lua_pop(luatcp_conf.Ltx, 1);
    return true;
}

static bool
luatcp_global_init(const struct Xconf *xconf)
{
    if (!luatcp_conf.script) {
        LOG(LEVEL_ERROR, "[-] LuaTcpProbe: must specify a lua script as probe by `--script`.\n");
        return false;
    }

    if (xconf->tx_thread_count!=1 || xconf->rx_handler_count!=1) {
        LOG(LEVEL_ERROR, "[-] LuaTcpProbe doesn't support multi-tx-threads or multi-handle-threads now.\n");
        return false;
    }

    int version;
    int x;

    /* Create Lua VM */
    luatcp_conf.Ltx = luaL_newstate();
    luatcp_conf.Lrx = luaL_newstate();
    luaL_openlibs(luatcp_conf.Ltx);
    luaL_openlibs(luatcp_conf.Lrx);

    /* Load the script. This will verify the syntax.*/
    x = luaL_loadfile(luatcp_conf.Ltx, luatcp_conf.script);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "FAIL: %s error loading: %s: %s for Tx\n", "SCRIPTING:",
            luatcp_conf.script, lua_tostring(luatcp_conf.Ltx, -1));
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        free(luatcp_conf.script);
        return false;
    }
    x = luaL_loadfile(luatcp_conf.Lrx, luatcp_conf.script);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "FAIL: %s error loading: %s: %s for Rx\n", "SCRIPTING:",
            luatcp_conf.script, lua_tostring(luatcp_conf.Ltx, -1));
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        free(luatcp_conf.script);
        return false;
    }

    /*
     * Lua: Start running the script and we can see global variables and funcs.
     * Just need to check for one VM because of same script.
     */
    LOG(LEVEL_WARNING, "LuaTcpProbe running script: %s\n", luatcp_conf.script);
    x = lua_pcall(luatcp_conf.Ltx, 0, 0, 0);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "[-]LuaTcpProbe: error running %s: %s for Tx\n",
            luatcp_conf.script, lua_tostring(luatcp_conf.Ltx, -1));
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        free(luatcp_conf.script);
        return false;
    }
    x = lua_pcall(luatcp_conf.Lrx, 0, 0, 0);
    if (x != LUA_OK) {
        LOG(LEVEL_ERROR, "[-]LuaTcpProbe: error running %s: %s for Rx\n",
            luatcp_conf.script, lua_tostring(luatcp_conf.Lrx, -1));
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        free(luatcp_conf.script);
        return false;
    }

    /**
     *Sync config
    */
    /*probe name*/
    lua_getglobal(luatcp_conf.Ltx, LUA_PROBE_VAR_PROBENAME);
    if (lua_isstring(luatcp_conf.Ltx, -1)==0) {
        LOG(LEVEL_ERROR, "[-]LuaTcpProbe: no `"LUA_PROBE_VAR_PROBENAME"` setting in script %s.\n",
            luatcp_conf.script);
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        free(luatcp_conf.script);
        return false;
    }
    LOG(LEVEL_INFO, "[LuaTcpProbe] "LUA_PROBE_VAR_PROBENAME": %s.\n", lua_tostring(luatcp_conf.Ltx, -1));
    lua_pop(luatcp_conf.Ltx, 1);

    /*probe type*/
    lua_getglobal(luatcp_conf.Ltx, LUA_PROBE_VAR_PROBETYPE);
    if (lua_isstring(luatcp_conf.Ltx, -1)==0) {
        LOG(LEVEL_ERROR, "[-]LuaTcpProbe: no `"LUA_PROBE_VAR_PROBETYPE"` setting in script %s.\n",
            luatcp_conf.script);
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        free(luatcp_conf.script);
        return false;
    }
    if (strcmp(lua_tostring(luatcp_conf.Ltx, -1), "tcp")!=0) {
        LOG(LEVEL_ERROR, "[-]LuaTcpProbe: need a tcp `"LUA_PROBE_VAR_PROBETYPE"` instead of %s type in %s.\n",
            lua_tostring(luatcp_conf.Ltx, -1), luatcp_conf.script);
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        free(luatcp_conf.script);
        return false;
    }
    /*multi mode*/
    /*multi num*/
    /*probe desc*/

    /**
     * Check tcp type callback funcs
    */
    if (!check_func_exist(LUA_PROBE_FUNC_MAKE_PAYLOAD)) {
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        free(luatcp_conf.script);
        return false;
    }
    if (!check_func_exist(LUA_PROBE_FUNC_GET_PAYLOAD_LEN)) {
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        free(luatcp_conf.script);
        return false;
    }
    if (!check_func_exist(LUA_PROBE_FUNC_HANDLE_RESPONSE)) {
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        free(luatcp_conf.script);
        return false;
    }
    if (!check_func_exist(LUA_PROBE_FUNC_CLOSE)) {
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        free(luatcp_conf.script);
        return false;
    }

    /**
     * exec global init
    */
    lua_getglobal(luatcp_conf.Ltx, LUA_PROBE_FUNC_GLOBAL_INIT);
    if (lua_isfunction(luatcp_conf.Ltx, -1)) {
        if (lua_pcall(luatcp_conf.Ltx, 0, 1, 0) != LUA_OK) {
            LOG(LEVEL_ERROR, "[-]LuaTcpProbe: func `"LUA_PROBE_FUNC_GLOBAL_INIT"` error in %s: %s\n",
                luatcp_conf.script, lua_tostring(luatcp_conf.Ltx, -1));
        }
        int ret = lua_toboolean(luatcp_conf.Ltx, -1);
        if (ret<=0) {
            LOG(LEVEL_ERROR, "[-]LuaTcpProbe: func `"LUA_PROBE_FUNC_GLOBAL_INIT"` failed in %s\n",
                luatcp_conf.script);
            return false;
        }
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
        LOG(LEVEL_ERROR, "[-]LuaTcpProbe: func `"LUA_PROBE_FUNC_MAKE_PAYLOAD"` execute error in %s: %s\n",
            luatcp_conf.script, lua_tostring(luatcp_conf.Ltx, -1));
        lua_settop(luatcp_conf.Ltx, 0);
        return 0;
    }

    if (lua_isstring(luatcp_conf.Ltx, -1)==0) {
        LOG(LEVEL_ERROR, "LuaTcpProbe: func `"LUA_PROBE_FUNC_MAKE_PAYLOAD"` return error in script %s.\n",
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
        LOG(LEVEL_ERROR, "[-]LuaTcpProbe: func `"LUA_PROBE_FUNC_GET_PAYLOAD_LEN"` execute error in %s: %s\n",
            luatcp_conf.script, lua_tostring(luatcp_conf.Lrx, -1));
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }

    if (lua_isinteger(luatcp_conf.Lrx, -1)==0) {
        LOG(LEVEL_ERROR, "LuaTcpProbe: func `"LUA_PROBE_FUNC_GET_PAYLOAD_LEN"` return error in script %s.\n",
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
    struct ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px,
    struct OutputItem *item)
{
    const char *ret;
    size_t ret_len;

    lua_getglobal(luatcp_conf.Lrx, LUA_PROBE_FUNC_HANDLE_RESPONSE);
    lua_pushstring(luatcp_conf.Lrx, ipaddress_fmt(target->ip_them).string);
    lua_pushinteger(luatcp_conf.Lrx, target->port_them);
    lua_pushstring(luatcp_conf.Lrx, ipaddress_fmt(target->ip_me).string);
    lua_pushinteger(luatcp_conf.Lrx, target->port_me);
    lua_pushinteger(luatcp_conf.Lrx, target->index);
    lua_pushlstring(luatcp_conf.Lrx, px, sizeof_px);

    if (lua_pcall(luatcp_conf.Lrx, 6, 4, 0) != LUA_OK) {
        LOG(LEVEL_ERROR, "[-]LuaTcpProbe: func `"LUA_PROBE_FUNC_HANDLE_RESPONSE"` execute error in %s: %s\n",
            luatcp_conf.script, lua_tostring(luatcp_conf.Lrx, -1));
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }

    if (lua_isboolean(luatcp_conf.Lrx, -4)==0) {
        LOG(LEVEL_ERROR, "LuaTcpProbe: func `"LUA_PROBE_FUNC_HANDLE_RESPONSE"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }
    if (lua_toboolean(luatcp_conf.Lrx, -4)>0) {
        item->level = Output_SUCCESS;
    } else {
        item->level = Output_FAILURE;
    }

    if (lua_isstring(luatcp_conf.Lrx, -3)==0) {
        LOG(LEVEL_ERROR, "LuaTcpProbe: func `"LUA_PROBE_FUNC_HANDLE_RESPONSE"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }
    ret = lua_tolstring(luatcp_conf.Lrx, -3, &ret_len);
    memcpy(item->classification, ret, ret_len);

    if (lua_isstring(luatcp_conf.Lrx, -2)==0) {
        LOG(LEVEL_ERROR, "LuaTcpProbe: func `"LUA_PROBE_FUNC_HANDLE_RESPONSE"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }
    ret = lua_tolstring(luatcp_conf.Lrx, -2, &ret_len);
    memcpy(item->reason, ret, ret_len);

    if (lua_isstring(luatcp_conf.Lrx, -1)==0) {
        LOG(LEVEL_ERROR, "LuaTcpProbe: func `"LUA_PROBE_FUNC_HANDLE_RESPONSE"` return error in script %s.\n",
            luatcp_conf.script);
        lua_settop(luatcp_conf.Lrx, 0);
        return 0;
    }
    ret = lua_tolstring(luatcp_conf.Lrx, -1, &ret_len);
    memcpy(item->report, ret, ret_len);

    lua_settop(luatcp_conf.Lrx, 0);
    return 0;
}

void luatcp_close()
{
    lua_getglobal(luatcp_conf.Ltx, LUA_PROBE_FUNC_CLOSE);
    if (lua_pcall(luatcp_conf.Ltx, 0, 0, 0) != LUA_OK) {
        LOG(LEVEL_ERROR, "[-]LuaTcpProbe: func `"LUA_PROBE_FUNC_CLOSE"` error in %s: %s\n",
            luatcp_conf.script, lua_tostring(luatcp_conf.Ltx, -1));
    }

    if (luatcp_conf.Ltx) {
        lua_close(luatcp_conf.Ltx);
    }
    if (luatcp_conf.Lrx) {
        lua_close(luatcp_conf.Lrx);
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
        "LuaTcpProbe let a specifies proper lua script as a tcp type probe. It "
        "will save a lot of time for us to write simple probes or test ideas. "
        "The example script(tcp-example.lua) could be found at lua-probes dir."
        " In a nutshell, we should set some global variables as probe config "
        "include:\n"
        "`"LUA_PROBE_VAR_PROBENAME"`\n"
        "`"LUA_PROBE_VAR_PROBETYPE"`\n"
        "`"LUA_PROBE_VAR_MULTIMODE"`\n"
        "`"LUA_PROBE_VAR_MULTINUM"`\n"
        "`"LUA_PROBE_VAR_ProbeDesc"`\n"
        "And set some global functions for calling back include:\n"
        "`"LUA_PROBE_FUNC_GLOBAL_INIT"`\n"
        "`"LUA_PROBE_FUNC_MAKE_PAYLOAD"`\n"
        "`"LUA_PROBE_FUNC_GET_PAYLOAD_LEN"`\n"
        "`"LUA_PROBE_FUNC_HANDLE_RESPONSE"`\n"
        "`"LUA_PROBE_FUNC_CLOSE"`\n"
        "NOTE: This is an experimental function and does not support more than "
        "one tx thread or rx-handle thread. Even though, we had 2 essential thread"
        " so be careful to thread-safe problems.",
    .global_init_cb                        = &luatcp_global_init,
    .make_payload_cb                       = &luatcp_make_payload,
    .get_payload_length_cb                 = &luatcp_get_payload_length,
    .validate_response_cb                  = NULL,
    .handle_response_cb                    = &luatcp_handle_response,
    .close_cb                              = &luatcp_close,
};
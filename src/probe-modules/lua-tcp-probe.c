#include "probe-modules.h"

#include "../version.h"
#include "../xconf.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"

#include <lua5.3/lua.h>
#include <lua5.3/lualib.h>
#include <lua5.3/lauxlib.h>

/*for internal x-ref*/
extern struct ProbeModule LuaTcpProbe;

struct LuaTcpConf {
    char *script;
    lua_State *Ltx; /*for tx thread, init and close*/
    lua_State *Lrx; /*for rx thread*/
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
        LOG(LEVEL_ERROR, "[-]LuaTcpProbe: error running: %s: %s\n",
            luatcp_conf.script, lua_tostring(luatcp_conf.Ltx, -1));
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        free(luatcp_conf.script);
        return false;
    }

    /*check probe type*/
    lua_getglobal(luatcp_conf.Ltx, "probe_type");
    if (lua_isstring(luatcp_conf.Ltx, -1)==0) {
        LOG(LEVEL_ERROR, "[-]LuaTcpProbe: no probe type setting in script %s.\n",
            luatcp_conf.script);
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        free(luatcp_conf.script);
        return false;
    }

    if (strcmp(lua_tostring(luatcp_conf.Ltx, -1), "tcp")!=0) {
        LOG(LEVEL_ERROR, "[-]LuaTcpProbe: need a tcp probe type instead of %s type in %s.\n",
            lua_tostring(luatcp_conf.Ltx, -1), luatcp_conf.script);
        lua_close(luatcp_conf.Ltx);
        lua_close(luatcp_conf.Lrx);
        free(luatcp_conf.script);
        return false;
    }

    return true;
}

void luatcp_close()
{
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
        "LuaTcpProbe could set a valid Lua script as tcp type probe.",
    .global_init_cb                        = &luatcp_global_init,
    .make_payload_cb                       = &probe_make_no_payload,
    .get_payload_length_cb                 = &probe_no_payload_length,
    .validate_response_cb                  = NULL,
    .handle_response_cb                    = &probe_just_report_banner,
    .close_cb                              = &probe_close_nothing,
};
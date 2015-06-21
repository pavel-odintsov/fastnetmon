#include <lua5.1/lua.hpp>

// Heh, we have luajit only for Debian Jessie and should think about custom compilation
// https://packages.debian.org/search?keywords=luajit

// This code will NOT work with lua 5.2 because 5.1 and 5.2 really incompatible: 
// http://lists.opensuse.org/opensuse-factory/2012-01/msg00265.html
// Ubuntu 14.04 also has it: http://packages.ubuntu.com/trusty/luajit

// apt-get install -y lua5.1 lua-json liblua5.1-dev 
// g++ lua_integration.cpp -lluajit-5.1

// Unfortunately, we haven't support for FFI in standard lua and should switch to luajit:
// Info about bundled modules to luajit: http://luajit.org/extensions.html
// apt-get install -y libluajit-5.1-dev
int main() {
    typedef struct netflow_struct { int packets; int bytes; } netflow_t;
    netflow_t flow;

    flow.packets = 55;
    flow.bytes = 77;

    lua_State* L = luaL_newstate(); 
    // load libraries
    luaL_openlibs(L);

    luaL_dofile(L, "json_parser.lua");    
    //luaL_dostring(L, "a = 10 + 5"); 
    //lua_getglobal(L, "a"); 
    //int i = lua_tointeger(L, -1); 
    //printf("%d\n", i); 
    lua_getfield(L, LUA_GLOBALSINDEX, "process_netflow");
    //lua_pushstring(L, "first_arg");

    lua_pushlightuserdata(L, (void*)&flow);

    // Call with 1 argumnents and 1 result
    lua_call(L, 1, 1);

    printf( "Lua gettop: %d\n", lua_gettop(L) );
    printf( "Boolean result: %d\n", lua_toboolean(L, -1) );

    lua_close(L); 

    return 0;
}

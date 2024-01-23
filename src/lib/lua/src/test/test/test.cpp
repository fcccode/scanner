// test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
// https://www.oreilly.com/library/view/creating-solid-apis/9781491986301/ch01.html

#include <Windows.h>


EXTERN_C_START
#include "..\..\lua\lauxlib.h"
#include "..\..\lua\lua.h"
#include "..\..\lua\lualib.h"
EXTERN_C_END


#ifdef _WIN64  
#ifdef _DEBUG
#pragma comment(lib, "..\\..\\x64\\Debug\\liblua.lib")
#else
#pragma comment(lib, "..\\..\\x64\\Release\\liblua.lib")
#endif
#else 
#ifdef _DEBUG
#pragma comment(lib, "..\\..\\Debug\\liblua.lib") 
#else
#pragma comment(lib, "..\\..\\Release\\liblua.lib")
#endif
#endif


void RunFile()
{
    lua_State * L = luaL_newstate();
    luaL_openlibs(L);
    luaL_dofile(L, "test.lua");
    lua_close(L);
}


void RunStr()
{
    const char * code = "for i=0, 5 do print(\'Hello, world!\') end";

    lua_State * s = luaL_newstate();
    luaL_openlibs(s);
    luaL_dostring(s, code); 
    lua_close(s);
}


int wikipedia(void)
/*
https://zh.wikipedia.org/wiki/Lua
*/
{
    // 建立一个Lua状态
    lua_State * L = luaL_newstate();

    // 装载并执行一个字符串
    if (luaL_dostring(L, "function foo (x,y) return x+y end")) {
        lua_close(L);
        return -1;
    }

    // 压入全局"foo"（上面定义的函数）的值到堆栈，跟随着整数5和3
    lua_getglobal(L, "foo");
    lua_pushinteger(L, 5);
    lua_pushinteger(L, 3);

    lua_call(L, 2, 1); // 调用有二个实际参数和一个返回值的函数
    printf("Result: %lld\n", lua_tointeger(L, -1)); // 打印在栈顶的项目的整数值
    lua_pop(L, 1); // 返回堆栈至最初状态

    lua_close(L); // 关闭Lua状态

    return 0;
}


int main()
{
    RunFile();
    RunStr();
    wikipedia();

    return 0;
}

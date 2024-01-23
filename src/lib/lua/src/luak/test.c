#include "test.h"

EXTERN_C_START
#include "..\lua\lauxlib.h"
#include "..\lua\lua.h"
#include "..\lua\lualib.h"
EXTERN_C_END


//////////////////////////////////////////////////////////////////////////////////////////////////


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


_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID Unload(_In_ struct _DRIVER_OBJECT * DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	PAGED_CODE();
}


EXTERN_C DRIVER_INITIALIZE DriverEntry;
//#pragma INITCODE
#pragma alloc_text(INIT, DriverEntry)
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
EXTERN_C NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(RegistryPath);

	if (!KD_DEBUGGER_NOT_PRESENT) {
		KdBreakPoint();//__debugbreak();
	}

	//if (*InitSafeBootMode) {
	//    return STATUS_ACCESS_DENIED;
	//}

	PAGED_CODE();

	DriverObject->DriverUnload = Unload;

	RunFile();
	RunStr();

	return status;
}

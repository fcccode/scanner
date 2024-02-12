// scan.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//


#include "pch.h"
#include "options.h"
#include "threads.h"


CHAR g_ExePath[MAX_PATH]{};


//////////////////////////////////////////////////////////////////////////////////////////////////


void banner()
{
    printf("Made by correy\r\n");
    printf("https://github.com/kouzhudong\r\n");
    printf("\r\n");
}


BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
/*

https://docs.microsoft.com/en-us/windows/console/registering-a-control-handler-function
*/
{
    switch (fdwCtrlType) {        
    case CTRL_C_EVENT:// Handle the CTRL-C signal.
        printf("Ctrl-C event\n\n");
        InterlockedIncrement(&g_stop_scan);
        return TRUE;        
    case CTRL_CLOSE_EVENT:// CTRL-CLOSE: confirm that the user wants to exit.
        printf("Ctrl-Close event\n\n");
        return TRUE;        
    case CTRL_BREAK_EVENT:// Pass other signals to the next handler.
        printf("Ctrl-Break event\n\n");
        return FALSE;
    case CTRL_LOGOFF_EVENT:
        printf("Ctrl-Logoff event\n\n");
        return FALSE;
    case CTRL_SHUTDOWN_EVENT:
        printf("Ctrl-Shutdown event\n\n");
        return FALSE;
    default:
        printf("control signal type:%d\n\n", fdwCtrlType);
        return FALSE;
    }
}


void init()
{
    GetExePath(g_ExePath, _ARRAYSIZE(g_ExePath) - 1);

}


int _cdecl wmain(_In_ int argc, _In_reads_(argc) WCHAR * argv[])
{
    int ret = ERROR_SUCCESS;

    setlocale(LC_CTYPE, ".936");

    banner();

    init();

    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        printf("\nERROR: Could not set control handler(LastError:%d)", GetLastError());
        return GetLastError();
    }

    if (!LoadNpcapDlls()) {
        fprintf(stderr, "Couldn't load Npcap\n");
        return ERROR_DLL_INIT_FAILED;
    }

    ret = ParseCommandLine(argc, argv);    

    return ret;
}

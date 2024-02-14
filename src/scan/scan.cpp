// scan.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//


#include "pch.h"
#include "threads.h"
#include "http.h"
#include "arp.h"
#include "ip.h"
#include "port.h"
#include "test.h"


CHAR g_ExePath[MAX_PATH]{};
CHAR g_Date[MAX_PATH];


//////////////////////////////////////////////////////////////////////////////////////////////////


void banner()
{
    printf("Made by correy\r\n");
    printf("https://github.com/kouzhudong\r\n");
    printf("\r\n");
}


int Usage(TCHAR * exe)
/*++
Routine Description
    Prints usage
--*/
{
    banner();

    printf("本程序的用法如下：\r\n");
    printf("用法概要：\"%ls\" 命令 地址 端口 选项 ...\r\n", exe);

    printf("命令：SYN等\r\n");
    printf("地址：包括IPv4/6以及IPv4子网掩码（0.0.0.0/0）\r\n");
    printf("端口：单个及范围（[m,n]）\r\n");

    printf("用SYN扫描IPv4全网（默认排除局域网和一些特殊的地址）：\"%ls\" SYN 443\r\n", exe);
    printf("用SYN扫描某个IPv4网段的某个端口：\"%ls\" SYN 0.0.0.0/0 443\r\n", exe);
    printf("用SYN扫描某个IPv4/6的所有的端口：\"%ls\" SYN IPv4/6 1-65535\r\n", exe);

    printf("\r\n");

    return ERROR_SUCCESS;
}


BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
/*

https://docs.microsoft.com/en-us/windows/console/registering-a-control-handler-function
*/
{
    string FileName;
    FileName = g_ExePath;
    FileName += "scan.db";
    WriteIPv4(FileName.c_str());

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


DWORD init()
{
    int ret = ERROR_SUCCESS;

    setlocale(LC_CTYPE, ".936");

    GetExePath(g_ExePath, _ARRAYSIZE(g_ExePath) - 1);

    SYSTEMTIME st;
    GetLocalTime(&st);

    //格式：2016-07-11
    sprintf_s(g_Date, "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);

    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        DWORD LastError = GetLastError();
        printf("\nERROR: Could not set control handler(LastError:%d)", LastError);
        return LastError;
    }

    if (!LoadNpcapDlls()) {
        fprintf(stderr, "Couldn't load Npcap\n");
        return ERROR_DLL_INIT_FAILED;
    }

    return ret;
}


int _cdecl wmain(_In_ int argc, _In_reads_(argc) WCHAR * argv[])
{
    int ret = init();
    if (ERROR_SUCCESS != ret) {
        return ret;
    }

    if (1 == argc) {
        return Usage(argv[0]);
    }

    else if (lstrcmpi(argv[1], L"Interface") == 0) {
        EnumAvailableInterface();
        GetAdapterNames();
        return ret;
    }

    else if (lstrcmpi(argv[1], L"test") == 0) {
        return test();
    }

    //主机/端口发现扫描
    else if (_wcsicmp(argv[1], L"ip") == 0) {
        return ip(--argc, ++argv);
    } else if (_wcsicmp(argv[1], L"port") == 0) {
        return port(--argc, ++argv);
    }

    //具体的协议扫描
    else if (_wcsicmp(argv[1], L"https") == 0) {
        //https(--argc, ++argv);
    } else if (_wcsicmp(argv[1], L"rdp") == 0) {
        //rdp(--argc, ++argv);
    } else if (_wcsicmp(argv[1], L"ssh") == 0) {
        //ssh(--argc, ++argv);
    } else if (_wcsicmp(argv[1], L"smtp") == 0) {
        //smtp(--argc, ++argv);
    } else if (_wcsicmp(argv[1], L"dns") == 0) {
        //dns(--argc, ++argv);
    }

    //漏洞扫描
    else if (_wcsicmp(argv[1], L"vul") == 0) {
        //vul(--argc, ++argv);
    }

    else if (lstrcmpi(argv[1], L"?") == 0) {
        return Usage(argv[0]);
    } else if (lstrcmpi(argv[1], L"h") == 0) {
        return Usage(argv[0]);
    } else if (lstrcmpi(argv[1], L"help") == 0) {
        return Usage(argv[0]);
    } else {
        return Usage(argv[0]);
    }

    return ERROR_SUCCESS;
}

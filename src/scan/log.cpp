#include "log.h"


Clog g_log;


//////////////////////////////////////////////////////////////////////////////////////////////////


void Clog::GetLogFile()
{
    TCHAR szPath[MAX_PATH] = {0};

    if (!GetModuleFileName(NULL, szPath, MAX_PATH)) {
        fprintf(stderr, "FILE:%hs, LINE:%d, LastError:%d.\r\n", __FILE__, __LINE__, GetLastError());
        return;
    }

    TCHAR * module = PathFindFileName(szPath);

    int n = lstrlen(szPath) - lstrlen(module);

    szPath[n] = 0;

    //////////////////////////////////////////////////////////////////////////////////////////////

    HRESULT hr = StringCchCopy(m_LogFile, _ARRAYSIZE(m_LogFile), szPath);
    _ASSERTE(S_OK == hr);
    BOOL B = PathAppend(m_LogFile, L"log.txt");
    _ASSERTE(B);
}


Clog::Clog()
{
    InitializeCriticalSection(&m_log_cs);
    setlocale(0, "chs");//支持写汉字。

    GetLogFile();
    
#pragma warning(push)
    //"'_wfopen': This function or variable may be unsafe. 
    //Consider using _wfopen_s instead. 
    //To disable deprecation, use _CRT_SECURE_NO_WARNINGS."
#pragma warning(disable:4996)
    m_hf = _tfopen(m_LogFile, L"at+");//, ccs=UNICODE 
#pragma warning(pop)
    
    _ASSERTE(m_hf);
}


Clog::~Clog()
{
    fclose(m_hf);
    DeleteCriticalSection(&m_log_cs);
}


void Clog::LogA(char const * Format, ...)
/*
因为文件是unicode的，所以这个函数也要写unicode。

还可以考虑加一个模块参数。

注意：Level只可取枚举的一个值，不能取多个。

改进：用va_arg实现获取各个参数的长度，然后动态计算实际需要的内存大小，最大支持NTSTRSAFE_MAX_CCH。
*/
{
    EnterCriticalSection(&m_log_cs);

    va_list args;
    va_start(args, Format);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t time[MAX_PATH] = {0};//格式：2016-07-11 17:35:54 
    int written = wsprintfW(time, L"%04d-%02d-%02d %02d:%02d:%02d\t",
                            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    written = fprintf(m_hf, "%ls", time);//这个函数下，\r\n是两个换行，所以只需一个\n即可。

    written = vfprintf(m_hf, Format, args);//指定为, ccs=UNICODE，这里崩溃。

    written = fflush(m_hf);

    va_end(args);

    LeaveCriticalSection(&m_log_cs);
}

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
    setlocale(0, "chs");//֧��д���֡�

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
��Ϊ�ļ���unicode�ģ������������ҲҪдunicode��

�����Կ��Ǽ�һ��ģ�������

ע�⣺Levelֻ��ȡö�ٵ�һ��ֵ������ȡ�����

�Ľ�����va_argʵ�ֻ�ȡ���������ĳ��ȣ�Ȼ��̬����ʵ����Ҫ���ڴ��С�����֧��NTSTRSAFE_MAX_CCH��
*/
{
    EnterCriticalSection(&m_log_cs);

    va_list args;
    va_start(args, Format);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t time[MAX_PATH] = {0};//��ʽ��2016-07-11 17:35:54 
    int written = wsprintfW(time, L"%04d-%02d-%02d %02d:%02d:%02d\t",
                            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    written = fprintf(m_hf, "%ls", time);//��������£�\r\n���������У�����ֻ��һ��\n���ɡ�

    written = vfprintf(m_hf, Format, args);//ָ��Ϊ, ccs=UNICODE�����������

    written = fflush(m_hf);

    va_end(args);

    LeaveCriticalSection(&m_log_cs);
}

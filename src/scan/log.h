#pragma once

#include "pch.h"

class Clog //log是个函数，clog也是个类。
{
public:
    Clog();
    ~Clog();
    void LogA(char const * Format, ...);

private:
    CRITICAL_SECTION m_log_cs;
    FILE * m_hf;
    WCHAR m_LogFile[MAX_PATH] = {0};

    void GetLogFile();
};


extern Clog g_log;


#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)


/*
既支持单字符也支持宽字符。
注意：第二个参数是单字符，可以为空，但不要为NULL，更不能省略。
*/
#define Log(Format, ...) \
{g_log.LogA("FILE:%s, LINE:%d, "##Format".\n", __FILENAME__, __LINE__, __VA_ARGS__);} //\r\n

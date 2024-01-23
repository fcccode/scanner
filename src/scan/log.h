#pragma once

#include "pch.h"

class Clog //log�Ǹ�������clogҲ�Ǹ��ࡣ
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
��֧�ֵ��ַ�Ҳ֧�ֿ��ַ���
ע�⣺�ڶ��������ǵ��ַ�������Ϊ�գ�����ҪΪNULL��������ʡ�ԡ�
*/
#define Log(Format, ...) \
{g_log.LogA("FILE:%s, LINE:%d, "##Format".\n", __FILENAME__, __LINE__, __VA_ARGS__);} //\r\n

/*
������Ҫ���ڴ�����������в���ѡ�
*/

#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


//https://msdn.microsoft.com/en-us/library/windows/desktop/ms738518%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
//��ʵ��IPV4��ֻ��This buffer should be large enough to hold at least 16 characters.
#define MAX_ADDRESS_STRING_LENGTH   64


//ʮ���ƵĶ˿��ַ����ĳ��ȡ���ʵ��󳤶���5����������Ϊ8��
#define MAX_PORT_STRING_LENGTH  5  //65535==FFFF 


//IPv4�ĵ��ַ����������ʽ��
#define IPV4_REGULAR R"((\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3}))"  


//IPv4�Ŀ��ַ����������ʽ��
#define IPV4_REGULARW LR"((\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3}))"  


//IPv4��������ĵ��ַ����������ʽ��
#define IPV4SUBNET_REGULAR (IPV4_REGULAR R"(/(\d{1,5}))")


//IPv4��������Ŀ��ַ����������ʽ��
#define IPV4SUBNET_REGULARW (IPV4_REGULARW LR"(/(\d{1,5}))")


//////////////////////////////////////////////////////////////////////////////////////////////////


int ParseCommandLine(_In_ int argc, _In_reads_(argc) WCHAR * argv[]);

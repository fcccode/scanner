/*
此文主要用于处理各种命令行参数选项。
*/

#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


//https://msdn.microsoft.com/en-us/library/windows/desktop/ms738518%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
//其实：IPV4的只需This buffer should be large enough to hold at least 16 characters.
#define MAX_ADDRESS_STRING_LENGTH   64


//十进制的端口字符串的长度。其实最大长度是5，可以设置为8。
#define MAX_PORT_STRING_LENGTH  5  //65535==FFFF 


//IPv4的单字符版的正则表达式。
#define IPV4_REGULAR R"((\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3}))"  


//IPv4的宽字符版的正则表达式。
#define IPV4_REGULARW LR"((\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3}))"  


//IPv4子网掩码的单字符版的正则表达式。
#define IPV4SUBNET_REGULAR (IPV4_REGULAR R"(/(\d{1,5}))")


//IPv4子网掩码的宽字符版的正则表达式。
#define IPV4SUBNET_REGULARW (IPV4_REGULARW LR"(/(\d{1,5}))")


//////////////////////////////////////////////////////////////////////////////////////////////////


int ParseCommandLine(_In_ int argc, _In_reads_(argc) WCHAR * argv[]);

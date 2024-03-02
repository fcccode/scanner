/*
功能：ICMP扫描。

最基本和强大的ICMP扫描是自己组装ICMP
其次是用RAW套接字。有不能用于欺骗等缺点。
最后是API，如：IcmpSendEcho2，Icmp6SendEcho2。
*/

#pragma once

#include "pch.h"

int Icmpv4Scan(PIN_ADDR DstIPv4);
int Icmpv4Scan(PIN_ADDR SrcIPv4, PIN_ADDR DstIPv4);
int Icmpv4Scan(PIN_ADDR DstIPv4, BYTE Mask);
int Icmpv6Scan(PIN6_ADDR DstIPv6);
int Icmpv6Scan(PIN6_ADDR DstIPv6, BYTE Mask);
